"""
syslog_classifier.py
--------------------
SBERTを用いたSyslogの意味ベース自動分類システム。

過去に解決したログを「参照データ」としてベクトル化し、
新規ログとの意味的な距離（コサイン類似度）で以下の3段階に分類します。

    Known             : スコア >= tau_high  → 解決済み事象。自動スルー
    Unknown Review    : tau_low <= スコア < tau_high → 週次でまとめて確認
    Unknown Strong    : スコア < tau_low    → 未知の事象。最優先で調査

Reference:
    Qiita: https://qiita.com/kkae1278
"""

import os
import random
import re
from datetime import datetime, timedelta
from typing import Any

import numpy as np
import openpyxl
import pandas as pd
import torch
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter
from sentence_transformers import SentenceTransformer, util


# ══════════════════════════════════════════════════════════════
# 3.0  台帳ロード
# ══════════════════════════════════════════════════════════════

def _read_excel_logs(
    filepath: str,
    sheet_name: str,
    required_cols: list[str],
    label: str,
) -> pd.DataFrame:
    """Excel シートを読み込み、必須列の存在と非 NaN を検証して返す内部関数。"""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"ファイルが見つかりません: {filepath}")
    df = pd.read_excel(filepath, sheet_name=sheet_name, dtype=str)
    for col in required_cols:
        if col not in df.columns:
            raise ValueError(f"必須列 '{col}' が '{sheet_name}' シートに存在しません。")
    df = df.dropna(subset=required_cols)
    print(f"[INFO] {label}を {len(df)} 件読み込みました（{filepath} / シート: {sheet_name}）")
    return df


def load_known_logs(filepath: str, sheet_name: str = "台帳") -> tuple[list[str], list[str]]:
    """
    Excel台帳から解決済みログを読み込む。

    Parameters
    ----------
    filepath   : resolved_logs.xlsx へのパス
    sheet_name : 読み込むシート名（デフォルト: "台帳"）

    Returns
    -------
    (log_ids, log_texts)
        log_ids   : 管理番号リスト  例) ["LOG-0001", "LOG-0002", ...]
        log_texts : ログ本文リスト
    """
    df = _read_excel_logs(filepath, sheet_name, ["管理番号", "ログ本文（raw）"], "既知ログ")
    return df["管理番号"].tolist(), df["ログ本文（raw）"].tolist()


# ══════════════════════════════════════════════════════════════
# 3.1  前処理（正規化）
# ══════════════════════════════════════════════════════════════

def normalize_syslog(line: str) -> str:
    """
    可変部を置換し、事象の「骨格」を取り出す。

    適用順序に注意:
        単純な数値への置換を最初に行うとIPアドレスや日付の一部まで
        破壊してしまうため、具体的なパターンから順に適用する。
    """
    s = line
    # 0. Cisco severity prefix（%SYS-5-CONFIG_I: など）— タイムスタンプより先に除去
    s = re.sub(r"%[A-Z0-9_]+-\d+-[A-Z0-9_]+:", "<SEV>", s)
    # 1. タイムスタンプ（ISO8601 / Cisco形式など）
    s = re.sub(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b", "<TS>", s)
    s = re.sub(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b", "<TS>", s)
    # 2. MACアドレス — IPv6より先に処理（aa:bb:cc:dd:ee:ff がIPv6パターンにも一致するため）
    s = re.sub(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b", "<MAC>", s)
    # 2a. IPv6アドレス — IPv4より先に処理（コロンが混在するため）
    #     プレースホルダーは <IPV> とする（<IP6> は後段で6が<NUM>置換されるため）
    s = re.sub(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b", "<IPV>", s)
    # 2b. IPv4アドレス
    s = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>", s)
    # 2c. プロセスID（kernel[12345]: / sshd[678]: など）コロンも含めて除去
    s = re.sub(r"\b\w+\[\d+\]:", "<PROC>", s)
    # 4. インターフェース名（GigabitEthernet0/1 → <IF>）
    s = re.sub(r"\b(?:GigabitEthernet|FastEthernet|Eth|Te|Ge)\d+(?:/\d+)*\b", "<IF>", s)
    # 5. 16進数
    s = re.sub(r"\b0x[0-9a-fA-F]+\b", "<HEX>", s)
    # 6. 英字と数字が直結するトークン内の数字（例: router01 → router<NUM>）
    s = re.sub(r"(?<=[a-zA-Z])\d+", "<NUM>", s)
    # 7. その他の数値
    s = re.sub(r"\b\d+\b", "<NUM>", s)
    # 連続するスペースを統合
    return re.sub(r"\s+", " ", s).strip()


# ══════════════════════════════════════════════════════════════
# 3.2  SBERT検知器
# ══════════════════════════════════════════════════════════════

class UnknownDetector:
    """
    SBERTを使って新規Syslogを既知ログと意味的に比較し、3段階に分類するクラス。

    Parameters
    ----------
    resolved_logs : 解決済みログの生テキストリスト（load_known_logs で取得）
    log_ids       : 各ログに対応する管理番号リスト（同上）
    model_name    : 使用するSentenceTransformerモデル名。
                    日本語ログのみを扱う場合は 'cl-tohoku/bert-base-japanese-v3'
                    等の日本語特化モデルの方が精度が向上する場合がある。
    batch_size    : エンコード時のバッチサイズ。ログ件数が多い場合はメモリに合わせて調整。
    """

    def __init__(
        self,
        resolved_logs: list[str],
        log_ids: list[str],
        model_name: str = "paraphrase-multilingual-MiniLM-L12-v2",
        batch_size: int = 64,
    ) -> None:
        """
        既知ログをベクトル化して検知器を初期化する。

        Parameters
        ----------
        resolved_logs : 解決済みログの生テキストリスト（load_known_logs で取得）
        log_ids       : 各ログに対応する管理番号リスト（同上）
        model_name    : SentenceTransformer モデル名。
                        日本語ログのみを扱う場合は
                        'cl-tohoku/bert-base-japanese-v3' 等の
                        日本語特化モデルの方が精度が向上する場合がある。
        batch_size    : エンコード時のバッチサイズ。
                        ログ件数が多い場合はメモリに合わせて調整。
        """
        self.model = SentenceTransformer(model_name)
        self.model_name = model_name
        self.log_ids = log_ids
        self.batch_size = batch_size

        print("[INFO] 既知ログのベクトル化を開始...")
        self.known_normed = [normalize_syslog(t) for t in resolved_logs]
        self.known_vecs = self.model.encode(
            self.known_normed, convert_to_tensor=True, batch_size=batch_size
        )
        print("[INFO] ベクトル化完了")

    # ──────────────────────────────────────────────────────────
    # 追加機能 A: ベクトルキャッシュ保存／読み込み
    # ──────────────────────────────────────────────────────────

    def save_cache(self, cache_path: str) -> None:
        """
        既知ログのベクトルと正規化テキスト・IDをファイルに保存する。

        台帳が変わらない限り次回起動時にエンコードをスキップできるため、
        ログ件数が多い環境で起動時間を大幅に短縮できる。

        Parameters
        ----------
        cache_path : 保存先パス（推奨拡張子: .npz）
        """
        vecs_np = self.known_vecs.cpu().numpy()
        np.savez(
            cache_path,
            vecs=vecs_np,
            normed=np.array(self.known_normed, dtype=object),
            ids=np.array(self.log_ids, dtype=object),
            model_name=np.array(self.model_name),
        )
        print(f"[INFO] キャッシュを保存しました: {cache_path}")

    @classmethod
    def load_cache(
        cls,
        cache_path: str,
        model_name: str = "paraphrase-multilingual-MiniLM-L12-v2",
        batch_size: int = 64,
    ) -> "UnknownDetector":
        """
        save_cache() で保存したキャッシュから検知器を復元する。

        Parameters
        ----------
        cache_path : save_cache() で指定したパス
        model_name : 保存時と同じモデル名を指定すること
        batch_size : detect() 時のバッチサイズ

        Returns
        -------
        UnknownDetector インスタンス（__init__ のエンコード処理をスキップ）

        Raises
        ------
        FileNotFoundError : cache_path が存在しない場合
        """
        if not os.path.exists(cache_path):
            raise FileNotFoundError(f"キャッシュファイルが見つかりません: {cache_path}")

        data = np.load(cache_path, allow_pickle=True)

        # キャッシュ生成時のモデルと一致するか検証
        if "model_name" in data:
            cached_model = str(data["model_name"])
            if cached_model != model_name:
                raise ValueError(
                    f"モデル名が一致しません。"
                    f"キャッシュ: '{cached_model}'  指定: '{model_name}'\n"
                    f"キャッシュを削除して再生成してください。"
                )

        instance = cls.__new__(cls)
        instance.model = SentenceTransformer(model_name)
        instance.model_name = model_name
        instance.batch_size = batch_size
        instance.known_normed = data["normed"].tolist()
        instance.log_ids = data["ids"].tolist()
        # encode() の出力と同じデバイスに載せる（GPU環境で cos_sim / cat のデバイス不一致を防ぐ）
        instance.known_vecs = torch.tensor(data["vecs"]).to(instance.model.device)
        print(f"[INFO] キャッシュから復元しました: {cache_path}  ({len(instance.log_ids)} 件)")
        return instance

    # ──────────────────────────────────────────────────────────

    def detect(
        self,
        new_logs: list[str],
        tau_low: float = 0.78,
        tau_high: float = 0.85,
        top_k: int = 3,
    ) -> list[dict[str, Any]]:
        """
        新規ログを分類する。

        Parameters
        ----------
        new_logs  : 検査対象の新規ログリスト
        tau_low   : Unknown Review / Unknown Strong の境界閾値
        tau_high  : Known / Unknown Review の境界閾値
        top_k     : スコア集計に使う上位 K 件数（1 = 旧来の最近傍1件）。
                    K 件の平均スコアで判定するため、1件の偶発的な高スコアに
                    引きずられにくくなる。台帳件数より大きい値は自動で丸める。

        Returns
        -------
        各ログの分類結果辞書リスト
            raw        : 元のログ文字列
            normed     : 正規化済みログ文字列（cluster_unknowns で使用）
            score      : Top-K 平均コサイン類似度（分類に使用）
            score_top1 : 最近傍1件のコサイン類似度（参考値）
            decision   : "known" / "unknown_review" / "unknown_strong"
            nearest_id : 最も近い既知ログの管理番号
            nearest    : 最も近い既知ログの正規化済み文字列
        """
        if not new_logs:
            return []

        new_normed = [normalize_syslog(t) for t in new_logs]
        new_vecs = self.model.encode(
            new_normed, convert_to_tensor=True, batch_size=self.batch_size
        )

        cos_sims = util.cos_sim(new_vecs, self.known_vecs)

        # Top-K の平均スコアで判定（K=1 は従来と同等）
        k = min(top_k, self.known_vecs.shape[0])
        top_scores, top_indices = torch.topk(cos_sims, k=k, dim=1)
        agg_scores    = top_scores.mean(dim=1)   # 分類に使う集約スコア
        max_scores    = top_scores[:, 0]          # 最近傍1件（参考）
        nearest_indices = top_indices[:, 0]       # 最近傍のインデックス

        results = []
        for i, agg_score in enumerate(agg_scores):
            s   = agg_score.item()
            s1  = max_scores[i].item()
            idx = nearest_indices[i].item()

            if s >= tau_high:
                decision = "known"
            elif s >= tau_low:
                decision = "unknown_review"
            else:
                decision = "unknown_strong"

            results.append({
                "raw":        new_logs[i],
                "normed":     new_normed[i],
                "_vec":       new_vecs[i].clone(),   # cluster_unknowns で再エンコード不要にする
                "score":      round(s,  4),
                "score_top1": round(s1, 4),
                "decision":   decision,
                "nearest_id": self.log_ids[idx],
                "nearest":    self.known_normed[idx],
            })
        return results

    def check_threshold(self) -> tuple[float, float]:
        """
        既知ログ間の類似度分布を表示し、閾値調整の参考にする（3.3節）。

        目安:
            tau_high は既知ログ間の類似度の中央値付近に設定
            tau_low  は tau_high から 0.05〜0.10 程度下げた値から試す
        """
        known_sim_matrix = util.cos_sim(self.known_vecs, self.known_vecs)
        mask = ~torch.eye(len(self.known_vecs), dtype=torch.bool)
        known_sims = known_sim_matrix[mask].cpu().numpy()

        # 正規化後に完全一致となったペア（同一テンプレート由来）は除外して統計を取る。
        # 含めると p75 が過小評価され、自動提案の閾値が低くなりすぎる。
        dedup_sims = known_sims[known_sims < 0.999]
        base_sims  = dedup_sims if len(dedup_sims) > 0 else known_sims

        p90 = float(np.percentile(base_sims, 90))
        suggested_high = round(p90, 2)
        suggested_low  = round(p90 - 0.07, 2)

        dup_ratio = 1.0 - len(dedup_sims) / len(known_sims)
        print(
            f"既知ログ間の類似度（重複除外後）: "
            f"min={base_sims.min():.3f}, "
            f"p25={np.percentile(base_sims, 25):.3f}, "
            f"p50={np.percentile(base_sims, 50):.3f}, "
            f"p75={np.percentile(base_sims, 75):.3f}, "
            f"p90={p90:.3f}, "
            f"max={base_sims.max():.3f}  "
            f"（重複ペア: {dup_ratio:.1%}）"
        )
        print(f"[推奨閾値] tau_high ≈ {suggested_high:.2f}  /  tau_low ≈ {suggested_low:.2f}"
              f"  （重複除外後 p90 を基準に算出。必ず実データで検証すること）")
        return suggested_high, suggested_low


    def update_known(self, new_raw: str, new_id: str) -> None:
        """
        確認済みの新規インシデントをメモリ内の既知セットに1件追加する。

        呼び出し後に save_cache() でキャッシュを更新し、
        add_to_ledger() で台帳 Excel にも追記すること。

        Parameters
        ----------
        new_raw : 追加する生ログ文字列
        new_id  : 管理番号（例: "LOG-0101"）
        """
        normed = normalize_syslog(new_raw)
        vec    = self.model.encode([normed], convert_to_tensor=True, batch_size=1)
        self.known_normed.append(normed)
        self.log_ids.append(new_id)
        self.known_vecs = torch.cat([self.known_vecs, vec], dim=0)
        print(f"[INFO] 既知ログを追加: {new_id}  （台帳合計: {len(self.log_ids)} 件）")


# ══════════════════════════════════════════════════════════════
# 追加機能 B: 分類サマリー表示
# ══════════════════════════════════════════════════════════════

def print_summary(results: list[dict[str, Any]]) -> None:
    """
    detect() の結果を集計してコンソールに出力する。

    Parameters
    ----------
    results : detector.detect() の戻り値

    出力例
    ------
    ┌─────────────────────────────┐
    │  分類結果サマリー           │
    ├──────────────────┬──────────┤
    │  known           │  3 (60%) │
    │  unknown_review  │  1 (20%) │
    │  unknown_strong  │  1 (20%) │
    │  合計            │  5       │
    └──────────────────┴──────────┘
    """
    if not results:
        print("[INFO] 分類結果が空です。")
        return

    total = len(results)
    counts: dict[str, int] = {"known": 0, "unknown_review": 0, "unknown_strong": 0}
    for r in results:
        counts[r["decision"]] = counts.get(r["decision"], 0) + 1

    labels = {
        "known":          "known          ",
        "unknown_review": "unknown_review ",
        "unknown_strong": "unknown_strong ",
    }
    print("┌──────────────────────────────────┐")
    print("│  分類結果サマリー                │")
    print("├──────────────────┬───────────────┤")
    for key, label in labels.items():
        n = counts[key]
        pct = n / total * 100
        print(f"│  {label}│ {n:>4} ({pct:5.1f}%) │")
    print(f"│  合計            │ {total:>4}          │")
    print("└──────────────────┴───────────────┘")


# ══════════════════════════════════════════════════════════════
# 追加機能 C: Unknown ログのクラスタリング
# ══════════════════════════════════════════════════════════════

def cluster_unknowns(
    results: list[dict[str, Any]],
    sim_threshold: float = 0.80,
) -> list[dict[str, Any]]:
    """
    Unknown ログ（review / strong）をコサイン類似度でグルーピングし、
    各 result に以下のキーを追加する。

        cluster_id        : クラスタ番号（known は -1）
        cluster_size      : そのクラスタに属するログ総件数
        is_representative : クラスタ内で最初に確定した代表ログなら True

    detect() が results に保存した "_vec" を再利用するため、
    モデルの再推論は発生しない。

    アルゴリズム:
        Greedy first-fit — 既存クラスタ代表との類似度 >= sim_threshold なら
        合流、なければ新クラスタを開始。O(N × C) で高速。

    Parameters
    ----------
    results       : detector.detect() の戻り値（"_vec" キーが必要）
    sim_threshold : 同一クラスタと見なす類似度の下限（デフォルト: 0.80）

    Returns
    -------
    cluster_id / cluster_size / is_representative を付与した results（in-place）
    """
    unknowns = [(i, r) for i, r in enumerate(results) if r["decision"] != "known"]

    if not unknowns:
        for r in results:
            r.setdefault("cluster_id", -1)
            r.setdefault("cluster_size", 1)
            r.setdefault("is_representative", False)
        return results

    # detect() で保存済みのベクトルを再利用（再エンコード不要）
    vecs = torch.stack([r["_vec"] for _, r in unknowns])

    # Greedy first-fit
    cluster_ids: list[int] = []
    rep_vecs:    list[torch.Tensor] = []
    next_id = 0

    for vec in vecs:
        assigned = -1
        for cid, rep in enumerate(rep_vecs):
            if util.cos_sim(vec.unsqueeze(0), rep.unsqueeze(0)).item() >= sim_threshold:
                assigned = cid
                break
        if assigned == -1:
            assigned = next_id
            rep_vecs.append(vec)
            next_id += 1
        cluster_ids.append(assigned)

    # クラスタサイズ
    size_map: dict[int, int] = {}
    for cid in cluster_ids:
        size_map[cid] = size_map.get(cid, 0) + 1

    # クラスタID・サイズを付与
    for (_, r), cid in zip(unknowns, cluster_ids):
        r["cluster_id"]   = cid
        r["cluster_size"] = size_map[cid]

    # 代表選択: クラスタ内で score が最も低い（未知度が最も高い）ログを代表にする
    # 入力順に依存せず、オペレータが最初に確認すべきログが代表となる
    best: dict[int, tuple[float, dict]] = {}   # cid → (min_score, result)
    for (_, r), cid in zip(unknowns, cluster_ids):
        if cid not in best or r["score"] < best[cid][0]:
            best[cid] = (r["score"], r)

    for r in results:
        r["is_representative"] = False
    for _, rep_r in best.values():
        rep_r["is_representative"] = True

    # known には既定値を付与
    for r in results:
        if r["decision"] == "known":
            r.setdefault("cluster_id", -1)
            r.setdefault("cluster_size", 1)
            r.setdefault("is_representative", False)

    # _vec は内部用途のみ — ここで除去して外部に漏れないようにする
    for r in results:
        r.pop("_vec", None)

    print(f"[INFO] Unknown {len(unknowns)} 件 → {next_id} クラスタに集約")
    return results


# ══════════════════════════════════════════════════════════════
# 4.  Excel出力
# ══════════════════════════════════════════════════════════════

def export_unknowns_to_excel(results: list[dict[str, Any]], output_path: str | None = None) -> str:
    """
    unknown_review / unknown_strong を Excel に出力する。

    cluster_unknowns() 適用済みの場合は以下の2シートを生成する:
        クラスタサマリー : 代表ログ1行/クラスタ。件数付き。オペレータが最初に見るシート
        要確認ログ       : 全 Unknown をクラスタ順に並べた詳細シート

    cluster_unknowns() 未適用の場合は従来通り「要確認ログ」1シートのみ。

    Parameters
    ----------
    results     : detector.detect()（+ cluster_unknowns()）の戻り値
    output_path : 出力先パス。None の場合はタイムスタンプ付きファイル名で自動生成

    Returns
    -------
    実際に保存されたファイルパス

    Notes
    -----
    openpyxl の PatternFill に渡す色は RRGGBB 形式（6桁）で指定する。
    ログ中の制御文字（ANSIエスケープ・NUL 等）は Excel に書き込めないため除去して出力する。
    """
    def _clean(v: Any) -> Any:
        return ILLEGAL_CHARACTERS_RE.sub("", v) if isinstance(v, str) else v

    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"unknown_logs_{ts}.xlsx"

    targets = [r for r in results if r["decision"] != "known"]
    has_cluster = bool(targets) and "cluster_id" in targets[0]

    # クラスタリング済み: Strong優先・件数多い順でクラスタをソートし、代表を先頭に
    if has_cluster:
        _priority = {"unknown_strong": 0, "unknown_review": 1}
        _reps      = [r for r in targets if r["is_representative"]]
        _reps_sorted = sorted(_reps, key=lambda r: (_priority.get(r["decision"], 9), -r["cluster_size"]))
        _cluster_order = {r["cluster_id"]: i for i, r in enumerate(_reps_sorted)}
        targets.sort(key=lambda r: (_cluster_order.get(r["cluster_id"], 999),
                                     0 if r["is_representative"] else 1))

    fill_strong = PatternFill(start_color="FFCCCC", end_color="FFCCCC", fill_type="solid")
    fill_review = PatternFill(start_color="FFFACC", end_color="FFFACC", fill_type="solid")
    fill_rep    = PatternFill(start_color="D6EAF8", end_color="D6EAF8", fill_type="solid")  # 代表行: 青系

    wb = openpyxl.Workbook()

    # ── シート①: クラスタサマリー（クラスタリング済み時のみ） ──────
    if has_cluster:
        ws_sum = wb.active
        ws_sum.title = "クラスタサマリー"

        sum_headers = ["判定", "クラスタID", "件数", "類似度(TopK平均)", "類似度(Top1)",
                       "最近傍の管理番号", "代表ログ（生）"]
        ws_sum.append(sum_headers)
        for cell in ws_sum[1]:
            cell.font = Font(bold=True)

        for r in targets:
            if not r["is_representative"]:
                continue
            ws_sum.append([
                r["decision"],
                r["cluster_id"],
                r["cluster_size"],
                r["score"],
                r["score_top1"],
                r["nearest_id"],
                _clean(r["raw"]),
            ])
            fill = fill_strong if r["decision"] == "unknown_strong" else fill_review
            for cell in ws_sum[ws_sum.max_row]:
                cell.fill = fill

        for i, w in enumerate([18, 12, 8, 18, 14, 20, 80], start=1):
            ws_sum.column_dimensions[get_column_letter(i)].width = w
        ws_sum.freeze_panes = "A2"   # ヘッダ行を固定

        ws_detail = wb.create_sheet("要確認ログ（詳細）")
    else:
        ws_detail = wb.active
        ws_detail.title = "要確認ログ"

    # ── シート②: 全ログ詳細 ───────────────────────────────────────
    if has_cluster:
        detail_headers = ["判定", "クラスタID", "件数", "類似度(TopK平均)", "類似度(Top1)",
                          "最近傍の管理番号", "最近傍ログ（正規化済）", "生ログ"]
    else:
        detail_headers = ["判定", "類似度スコア", "最近傍の管理番号", "最近傍ログ（正規化済）", "生ログ"]

    ws_detail.append(detail_headers)
    for cell in ws_detail[1]:
        cell.font = Font(bold=True)

    for r in targets:
        if has_cluster:
            row = [
                r["decision"],
                r["cluster_id"],
                r["cluster_size"] if r["is_representative"] else "",
                r["score"],
                r["score_top1"],
                r["nearest_id"],
                r["nearest"],
                r["raw"],
            ]
            # 代表行は青、それ以外は判定色
            fill = fill_rep if r["is_representative"] else (
                fill_strong if r["decision"] == "unknown_strong" else fill_review
            )
        else:
            row = [r["decision"], round(r["score"], 4), r["nearest_id"], r["nearest"], r["raw"]]
            fill = fill_strong if r["decision"] == "unknown_strong" else fill_review

        ws_detail.append([_clean(v) for v in row])
        for cell in ws_detail[ws_detail.max_row]:
            cell.fill = fill

    if has_cluster:
        for i, w in enumerate([18, 12, 8, 18, 14, 20, 60, 80], start=1):
            ws_detail.column_dimensions[get_column_letter(i)].width = w
    else:
        for i, w in enumerate([18, 16, 20, 60, 80], start=1):
            ws_detail.column_dimensions[get_column_letter(i)].width = w
    ws_detail.freeze_panes = "A2"   # ヘッダ行を固定

    wb.save(output_path)
    n_clusters = len({r["cluster_id"] for r in targets}) if has_cluster else len(targets)
    print(f"[INFO] 出力完了: {output_path}  （要確認: {len(targets)} 件 / {n_clusters} クラスタ）")
    return output_path


# ══════════════════════════════════════════════════════════════
# 5.  台帳フィードバック
# ══════════════════════════════════════════════════════════════

def add_to_ledger(
    filepath: str,
    log_id: str,
    raw_text: str,
    memo: str = "",
    sheet_name: str = "台帳",
) -> None:
    """
    確認済みの新規インシデントを台帳 Excel に追記する。

    UnknownDetector.update_known() → save_cache() と組み合わせて
    以下の順で呼び出すことで台帳とキャッシュを一貫して更新できる。

        add_to_ledger(ledger_path, "LOG-0101", raw, "原因: ...")
        detector.update_known(raw, "LOG-0101")
        detector.save_cache(cache_path)

    Parameters
    ----------
    filepath   : 台帳 Excel ファイルパス
    log_id     : 管理番号（例: "LOG-0101"）
    raw_text   : 生ログ文字列
    memo       : 備考・対応内容
    sheet_name : 書き込み先シート名（デフォルト: "台帳"）

    Raises
    ------
    FileNotFoundError : filepath が存在しない場合
    ValueError        : sheet_name が見つからない場合
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"台帳ファイルが見つかりません: {filepath}")

    wb = openpyxl.load_workbook(filepath)
    if sheet_name not in wb.sheetnames:
        raise ValueError(f"シート '{sheet_name}' が見つかりません。")

    wb[sheet_name].append([log_id, raw_text, memo])
    wb.save(filepath)
    print(f"[INFO] 台帳に追記しました: {log_id}  （{filepath}）")


# ══════════════════════════════════════════════════════════════
# 6.  テキストファイル入力
# ══════════════════════════════════════════════════════════════

def load_new_logs_from_text(filepath: str, encoding: str = "utf-8") -> list[str]:
    """
    生テキストファイル（.log / .txt）から1行1ログで読み込む。

    実際の syslog ファイルをそのまま渡せるため、
    Excel 変換なしに検査を開始できる。

    Parameters
    ----------
    filepath : テキストファイルパス
    encoding : ファイルエンコーディング（デフォルト: utf-8）

    Returns
    -------
    ログ文字列のリスト（空行・# で始まるコメント行は除外）

    Raises
    ------
    FileNotFoundError : filepath が存在しない場合
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"ファイルが見つかりません: {filepath}")

    with open(filepath, encoding=encoding) as f:
        logs = [
            line.rstrip("\n")
            for line in f
            if line.strip() and not line.startswith("#")
        ]

    print(f"[INFO] 新規ログを {len(logs)} 件読み込みました（{filepath}）")
    return logs


# ══════════════════════════════════════════════════════════════
# サンプル実行
# ══════════════════════════════════════════════════════════════

def _create_sample_ledger(path: str = "resolved_logs.xlsx", seed: int = 42) -> None:
    """
    動作確認用のサンプル台帳を100件生成する。

    26カテゴリ（リンク障害・BGP・認証・ハードウェア等）にわたる
    テンプレートからランダムな変数（IP・ホスト・インターフェース等）を
    埋め込んでリアルなSyslogを生成する。
    """
    rng = random.Random(seed)

    # (ログテンプレート, 備考)
    templates = [
        # ── リンク/インターフェース ──────────────────────────────────
        ("{host} Link down on GigabitEthernet{a}/{b}",                         "ケーブル断。現地確認・復旧済み"),
        ("{host} Interface GigabitEthernet{a}/{b} changed state to down",       "インターフェース障害。部品交換済み"),
        ("{host} Interface FastEthernet{a}/{b} is up, line protocol is up",     "リンク復旧確認"),
        ("{host} GigabitEthernet{a}/{b}: duplex mismatch detected",             "デュプレックス設定ミス。修正済み"),
        ("{host} Line protocol on Interface GigabitEthernet{a}/{b} changed state to up", "リンクアップ確認"),
        # ── BGP/ルーティング ─────────────────────────────────────────
        ("{host} BGP session with {ip} reset by peer",                          "ルータ再起動による一時断。監視除外済み"),
        ("{host} BGP-5-ADJCHANGE: neighbor {ip} Down BGP Notification sent",    "BGP障害。経路切替確認済み"),
        ("{host} OSPF-5-ADJCHG: Nbr {ip} on GigabitEthernet{a}/{b} from FULL to DOWN", "OSPF隣接断。回線障害起因"),
        ("{host} BGP session with {ip} established",                            "BGP再確立確認"),
        ("{host} OSPF neighbor {ip} is up on GigabitEthernet{a}/{b}",          "OSPF隣接復旧"),
        # ── 認証 ──────────────────────────────────────────────────────
        ("{host} Authentication failed for user {user} from {ip}",              "パスワード誤入力。本人確認済み"),
        ("{host} SSH: User {user} authenticated from {ip}",                     "正常SSH認証"),
        ("{host} User {user} login failed {n} times, account locked",           "アカウントロック。ヘルプデスク対応済み"),
        ("{host} Failed password for {user} from {ip} port {n} ssh2",          "ブルートフォース検知。ACL追加済み"),
        ("{host} Accepted publickey for {user} from {ip}",                      "公開鍵認証ログイン。正常"),
        # ── CPU/メモリ ────────────────────────────────────────────────
        ("{host} CPU utilization exceeded {n} percent threshold",               "CPUスパイク。プロセス確認済み"),
        ("{host} Memory utilization at {n}%, threshold exceeded",               "メモリ高使用率。再起動で解消"),
        ("{host} High CPU usage detected: {n}% for process snmpd",              "SNMPプロセス暴走。再起動済み"),
        # ── ハードウェア ──────────────────────────────────────────────
        ("{host} Fan failure detected in slot {n}",                             "ファン故障。部品交換済み"),
        ("{host} Temperature sensor {n} exceeded threshold: {n2} degrees Celsius", "温度警報。空調調整済み"),
        ("{host} Power supply unit {n} failed",                                 "電源ユニット障害。冗長系に切替"),
        ("{host} Disk usage at {n}%, threshold exceeded",                       "ディスク逼迫。不要ログ削除済み"),
        # ── STP/VLAN ─────────────────────────────────────────────────
        ("{host} STP: Topology change detected on VLAN {n}",                   "STPトポロジ変更。スイッチ障害起因"),
        ("{host} VLAN {n} state changed to active",                             "VLAN設定変更反映"),
        # ── DHCP/NTP ─────────────────────────────────────────────────
        ("{host} DHCP pool {n} exhausted",                                      "DHCPアドレス枯渇。プール拡張済み"),
        ("{host} NTP: synchronization lost",                                    "NTP同期断。サーバ障害起因"),
    ]

    hosts = [f"sw{i:02d}" for i in range(1, 11)] + [f"rt{i:02d}" for i in range(1, 6)]
    users  = ["admin", "operator", "noc-user", "backup", "monitor"]

    def rand_ip() -> str:
        return f"{rng.choice([10, 172, 192])}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"

    def rand_ts() -> str:
        dt = datetime(2025, 1, 1) + timedelta(
            days=rng.randint(0, 364),
            hours=rng.randint(0, 23),
            minutes=rng.randint(0, 59),
            seconds=rng.randint(0, 59),
        )
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    rows = []
    for i in range(100):
        tmpl, desc = templates[i % len(templates)]
        host = rng.choice(hosts)
        text = tmpl.format(
            host=host,
            a=rng.randint(0, 3),
            b=rng.randint(0, 24),
            ip=rand_ip(),
            n=rng.randint(1, 99),
            n2=rng.randint(40, 80),
            user=rng.choice(users),
        )
        rows.append({
            "管理番号": f"LOG-{i + 1:04d}",
            "ログ本文（raw）": f"{rand_ts()} {text}",
            "概要/備考": desc,
        })

    pd.DataFrame(rows).to_excel(path, sheet_name="台帳", index=False)
    print(f"[INFO] サンプル台帳生成: {path}  (100件)")


def load_new_logs(filepath: str = "syslog_this_week.xlsx", sheet_name: str = "今週のSyslog") -> list[str]:
    """
    Excelファイルの指定シートから今週の新規Syslogを読み込む。

    Parameters
    ----------
    filepath   : Excelファイルパス（resolved_logs.xlsx と同じファイルでも可）
    sheet_name : 読み込むシート名（デフォルト: "今週のSyslog"）

    Returns
    -------
    ログ文字列のリスト
    """
    df = _read_excel_logs(filepath, sheet_name, ["ログ本文（raw）"], "新規ログ")
    return df["ログ本文（raw）"].tolist()


def _create_sample_syslog_sheet(
    filepath: str = "syslog_this_week.xlsx",
    sheet_name: str = "今週のSyslog",
    n_logs: int = 5000,
    seed: int = 0,
) -> None:
    """
    動作確認用のSyslogシートを n_logs 件生成する。

    分類結果が分かりやすくなるよう、意図的に3種の比率で構成する:
        Known (~70%)         : 台帳と同一テンプレート・変数違いのみ
        Unknown Review (~15%): 台帳と似た表現だが語彙が異なる
        Unknown Strong (~15%): 台帳に存在しないカテゴリの事象
    """
    rng = random.Random(seed)

    hosts = [f"sw{i:02d}" for i in range(1, 16)] + [f"rt{i:02d}" for i in range(1, 8)]
    users = ["admin", "operator", "noc-user", "root", "sysadmin", "backup"]

    def rand_ip() -> str:
        return f"{rng.choice([10, 172, 192])}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"

    def rand_ts() -> str:
        dt = datetime(2026, 2, 1) + timedelta(
            days=rng.randint(0, 6),
            hours=rng.randint(0, 23),
            minutes=rng.randint(0, 59),
            seconds=rng.randint(0, 59),
        )
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    def r(lo: int, hi: int) -> int:
        return rng.randint(lo, hi)

    # ── Known: 台帳と同じテンプレート（変数のみ差し替え）────────────
    known_templates = [
        lambda: f"{rng.choice(hosts)} Link down on GigabitEthernet{r(0,3)}/{r(0,24)}",
        lambda: f"{rng.choice(hosts)} Interface GigabitEthernet{r(0,3)}/{r(0,24)} changed state to down",
        lambda: f"{rng.choice(hosts)} Interface FastEthernet{r(0,3)}/{r(0,24)} is up, line protocol is up",
        lambda: f"{rng.choice(hosts)} BGP session with {rand_ip()} reset by peer",
        lambda: f"{rng.choice(hosts)} BGP-5-ADJCHANGE: neighbor {rand_ip()} Down BGP Notification sent",
        lambda: f"{rng.choice(hosts)} OSPF-5-ADJCHG: Nbr {rand_ip()} on GigabitEthernet{r(0,1)}/{r(0,24)} from FULL to DOWN",
        lambda: f"{rng.choice(hosts)} Authentication failed for user {rng.choice(users)} from {rand_ip()}",
        lambda: f"{rng.choice(hosts)} SSH: User {rng.choice(users)} authenticated from {rand_ip()}",
        lambda: f"{rng.choice(hosts)} User {rng.choice(users)} login failed {r(3,10)} times, account locked",
        lambda: f"{rng.choice(hosts)} CPU utilization exceeded {r(80,99)} percent threshold",
        lambda: f"{rng.choice(hosts)} Memory utilization at {r(80,99)}%, threshold exceeded",
        lambda: f"{rng.choice(hosts)} Fan failure detected in slot {r(1,4)}",
        lambda: f"{rng.choice(hosts)} Temperature sensor {r(1,3)} exceeded threshold: {r(45,75)} degrees Celsius",
        lambda: f"{rng.choice(hosts)} Power supply unit {r(1,2)} failed",
        lambda: f"{rng.choice(hosts)} Disk usage at {r(85,99)}%, threshold exceeded",
        lambda: f"{rng.choice(hosts)} STP: Topology change detected on VLAN {r(1,100)}",
        lambda: f"{rng.choice(hosts)} DHCP pool {r(1,5)} exhausted",
        lambda: f"{rng.choice(hosts)} NTP: synchronization lost",
        lambda: f"{rng.choice(hosts)} Failed password for {rng.choice(users)} from {rand_ip()} port {r(1024,65535)} ssh2",
        lambda: f"{rng.choice(hosts)} High CPU usage detected: {r(80,99)}% for process snmpd",
    ]

    # ── Unknown Review: 似た意味・異なる語彙 ─────────────────────────
    review_templates = [
        lambda: f"{rng.choice(hosts)} Interface GigabitEthernet{r(0,3)}/{r(0,24)} went administratively down",
        lambda: f"{rng.choice(hosts)} BGP: neighbor {rand_ip()} reset, hold time expired",
        lambda: f"{rng.choice(hosts)} Login attempt blocked for user {rng.choice(users)} from {rand_ip()}",
        lambda: f"{rng.choice(hosts)} Routing process OSPF ID {r(1,9)} terminating abnormally",
        lambda: f"{rng.choice(hosts)} Overtemperature condition on module {r(1,4)}: {r(45,75)}C",
        lambda: f"{rng.choice(hosts)} Process memory low: {r(5,20)}% free remaining",
        lambda: f"{rng.choice(hosts)} NTP server {rand_ip()} is unreachable",
        lambda: f"{rng.choice(hosts)} Address pool for VLAN {r(1,100)} nearly exhausted: {r(90,99)}% used",
        lambda: f"{rng.choice(hosts)} Spanning tree root change on VLAN {r(1,100)}",
        lambda: f"{rng.choice(hosts)} Repeated authentication failures for {rng.choice(users)} — possible brute force",
    ]

    # ── Unknown Strong: 台帳に存在しない新種カテゴリ ─────────────────
    strong_templates = [
        lambda: f"{rng.choice(hosts)} Kernel panic - not syncing: VFS: Unable to mount root fs",
        lambda: f"{rng.choice(hosts)} SSL/TLS certificate for {rand_ip()} has expired",
        lambda: f"{rng.choice(hosts)} LACP: Port-channel{r(1,8)} member port GigabitEthernet{r(0,3)}/{r(0,24)} timeout",
        lambda: f"{rng.choice(hosts)} QoS policy-map violation on GigabitEthernet{r(0,3)}/{r(0,24)}: {r(100,9999)} packets dropped",
        lambda: f"{rng.choice(hosts)} MPLS LDP: Session to {rand_ip()} went down",
        lambda: f"{rng.choice(hosts)} IPSec IKE SA expired for peer {rand_ip()}",
        lambda: f"{rng.choice(hosts)} ErrDisable recovery scheduled for GigabitEthernet{r(0,3)}/{r(0,24)} (reason: bpduguard)",
        lambda: f"{rng.choice(hosts)} NFS mount timeout from {rand_ip()}:/vol{r(1,9)}/data",
        lambda: f"{rng.choice(hosts)} RADIUS server {rand_ip()} not responding to auth requests",
        lambda: f"{rng.choice(hosts)} Hardware watchdog timer expired — system will reload in {r(30,120)} seconds",
        lambda: f"{rng.choice(hosts)} ARP table overflow: {r(1000,9999)} entries, limit {r(500,999)}",
        lambda: f"{rng.choice(hosts)} Routing table corruption detected — RIB inconsistency",
    ]

    n_known  = int(n_logs * 0.70)
    n_review = int(n_logs * 0.15)
    n_strong = n_logs - n_known - n_review

    logs: list[str] = []
    for _ in range(n_known):
        logs.append(f"{rand_ts()} {rng.choice(known_templates)()}")
    for _ in range(n_review):
        logs.append(f"{rand_ts()} {rng.choice(review_templates)()}")
    for _ in range(n_strong):
        logs.append(f"{rand_ts()} {rng.choice(strong_templates)()}")

    rng.shuffle(logs)

    df = pd.DataFrame({"ログ本文（raw）": logs})
    df.to_excel(filepath, sheet_name=sheet_name, index=False)
    print(f"[INFO] サンプルSyslogシート生成: {filepath}  ({n_logs}件 — Known:{n_known} / Review:{n_review} / Strong:{n_strong})")


if __name__ == "__main__":
    LEDGER_PATH = "resolved_logs.xlsx"
    SYSLOG_PATH = "syslog_this_week.xlsx"
    CACHE_PATH  = "known_vecs.npz"

    # 初回のみ: サンプルファイルがなければ生成する
    if not os.path.exists(LEDGER_PATH):
        _create_sample_ledger(LEDGER_PATH)
    if not os.path.exists(SYSLOG_PATH):
        _create_sample_syslog_sheet(SYSLOG_PATH)

    # 1. 台帳からロード
    log_ids, log_texts = load_known_logs(LEDGER_PATH, sheet_name="台帳")

    # 2. 検知器を初期化（キャッシュがあれば再利用、なければ生成して保存）
    if os.path.exists(CACHE_PATH):
        detector = UnknownDetector.load_cache(CACHE_PATH)
    else:
        detector = UnknownDetector(resolved_logs=log_texts, log_ids=log_ids)
        detector.save_cache(CACHE_PATH)

    # 3. 類似度分布から閾値を自動提案（必要に応じて手動上書き）
    suggested_high, suggested_low = detector.check_threshold()
    # ↓ 実データで動作確認後に適切な値に変更すること
    tau_high = suggested_high
    tau_low  = suggested_low

    # 4. 新規 Syslog を読み込んで検査
    #    Excel: load_new_logs()           テキスト: load_new_logs_from_text()
    new_logs = load_new_logs(SYSLOG_PATH, sheet_name="今週のSyslog")
    results  = detector.detect(new_logs, tau_high=tau_high, tau_low=tau_low, top_k=3)

    # 5. Unknown ログをクラスタリング（同一原因の大量アラートを集約）
    results = cluster_unknowns(results, sim_threshold=0.80)

    # 6. 分類結果のサマリーを表示
    print_summary(results)

    # 7. 結果をExcelに出力（クラスタサマリー + 詳細の2シート構成）
    export_unknowns_to_excel(results)

    # ── 台帳フィードバック例（Unknown Strong を確認後に追記する場合） ──
    # unknowns = [r for r in results if r["decision"] == "unknown_strong"]
    # if unknowns:
    #     target = unknowns[0]                        # 先頭の Unknown Strong を例示
    #     new_id = f"LOG-{len(log_ids) + 1:04d}"
    #     add_to_ledger(LEDGER_PATH, new_id, target["raw"], "原因調査済み。対応完了")
    #     detector.update_known(target["raw"], new_id)
    #     detector.save_cache(CACHE_PATH)
