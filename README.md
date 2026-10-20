# syslog_classifier

SBERT を用いた Syslog の意味ベース自動分類システム。

過去に解決したログを「参照台帳」としてベクトル化し、新規ログとの意味的な距離（コサイン類似度）で以下の 3 段階に自動分類します。

| 判定 | 条件 | 対応 |
|---|---|---|
| **Known** | スコア >= tau_high | 解決済み事象。自動スルー |
| **Unknown Review** | tau_low <= スコア < tau_high | 週次でまとめて確認 |
| **Unknown Strong** | スコア < tau_low | 未知の事象。最優先で調査 |

同一原因の大量アラートはコサイン類似度でクラスタリングし、代表ログ 1 行に集約して Excel に出力します。

---

## 動作環境

- Python 3.10 以上
- GPU は不要（CPU のみで動作）

## インストール

```bash
pip install -r requirements.txt
```

## クイックスタート

```bash
python syslog_classifier.py
```

初回実行時はサンプルの台帳（`resolved_logs.xlsx`）と Syslog ファイル（`syslog_this_week.xlsx`）が自動生成されます。
分類結果は `unknown_logs_YYYYMMDD_HHMMSS.xlsx` に保存されます。

---

## ファイル構成

```
syslog_classifier.py   # 本体
requirements.txt       # 依存パッケージ
resolved_logs.xlsx     # 既知ログ台帳（初回自動生成）
syslog_this_week.xlsx  # 今週の新規 Syslog（初回自動生成）
known_vecs.npz         # ベクトルキャッシュ（初回自動生成）
unknown_logs_*.xlsx    # 分類結果出力
```

---

## 使い方

### 1. 台帳の準備

`resolved_logs.xlsx` の「台帳」シートに解決済みログを登録します。

| 管理番号 | ログ本文（raw） | 概要/備考 |
|---|---|---|
| LOG-0001 | 2025-01-10 09:12:34 sw01 Link down on GigabitEthernet0/1 | ケーブル断。現地対応済み |
| LOG-0002 | 2025-01-11 14:05:01 rt01 BGP session reset by peer | ルータ再起動。監視除外済み |

### 2. 新規 Syslog の準備

**Excel の場合** — `syslog_this_week.xlsx` の「今週のSyslog」シートに「ログ本文（raw）」列を作成して貼り付けます。

**テキストファイルの場合** — `load_new_logs_from_text()` を使います。

```python
from syslog_classifier import load_new_logs_from_text
logs = load_new_logs_from_text("syslog_today.log")
```

`#` で始まる行と空行は自動的に除外されます。

### 3. 実行

```python
from syslog_classifier import (
    UnknownDetector, load_known_logs, load_new_logs,
    cluster_unknowns, print_summary, export_unknowns_to_excel,
)

log_ids, log_texts = load_known_logs("resolved_logs.xlsx")
detector = UnknownDetector(resolved_logs=log_texts, log_ids=log_ids)

# 閾値の目安を確認（初回必須）
tau_high, tau_low = detector.check_threshold()

new_logs = load_new_logs("syslog_this_week.xlsx")
results  = detector.detect(new_logs, tau_high=tau_high, tau_low=tau_low, top_k=3)
results  = cluster_unknowns(results)

print_summary(results)
export_unknowns_to_excel(results)
```

---

## 閾値チューニング

`check_threshold()` の出力を参考に `tau_high` / `tau_low` を調整します。

```
既知ログ間の類似度（重複除外後）: min=0.154, p50=0.437, p90=0.638
[推奨閾値] tau_high ≈ 0.64  /  tau_low ≈ 0.57
```

推奨値はあくまで出発点です。Unknown Strong の比率が 10〜20% 程度になるよう以下の手順でスキャンしてください。

```python
for hi, lo in [(0.70, 0.63), (0.73, 0.66), (0.75, 0.68), (0.78, 0.71)]:
    rs = detector.detect(new_logs, tau_high=hi, tau_low=lo, top_k=3)
    kn = sum(1 for r in rs if r["decision"] == "known")
    st = sum(1 for r in rs if r["decision"] == "unknown_strong")
    print(f"tau_high={hi} / tau_low={lo}  →  Known={kn}  Strong={st}")
```

---

## 台帳へのフィードバック

Unknown Strong を調査して既知と確定したら、台帳・メモリ・キャッシュを以下の 3 点セットで更新します。

```python
from syslog_classifier import add_to_ledger

add_to_ledger("resolved_logs.xlsx", "LOG-0101", raw_log, "原因: ...")
detector.update_known(raw_log, "LOG-0101")
detector.save_cache("known_vecs.npz")
```

台帳を育てるほど Known の精度が向上し、Unknown Strong の件数が自然に減少します。

---

## ベクトルキャッシュ

台帳が変わらない限り、2 回目以降の起動はキャッシュ（`known_vecs.npz`）からベクトルを復元してエンコードをスキップします。

```python
detector = UnknownDetector.load_cache("known_vecs.npz")
```

台帳を更新した場合はキャッシュを削除するか `save_cache()` で上書きしてください。

---

## 前処理（normalize_syslog）

以下のパターンを汎用トークンに置換し、変数部分の差異を吸収します。

| パターン | 置換後 | 例 |
|---|---|---|
| ISO8601 / Cisco タイムスタンプ | `<TS>` | `2026-01-10 09:12:34` |
| IPv4 アドレス | `<IP>` | `192.168.1.1` |
| IPv6 アドレス | `<IPV>` | `fe80::1` |
| MAC アドレス | `<MAC>` | `aa:bb:cc:dd:ee:ff` |
| インターフェース名 | `<IF>` | `GigabitEthernet0/1` |
| 16 進数 | `<HEX>` | `0x1a2b` |
| プロセス ID | `<PROC>` | `kernel[12345]:` |
| Cisco severity prefix | `<SEV>` | `%SYS-5-CONFIG_I:` |
| その他の数値 | `<NUM>` | `port 22`, `slot 3` |

---

## モデルの変更

デフォルトモデルは多言語対応の `paraphrase-multilingual-MiniLM-L12-v2` です。
日本語ログが大半の環境では日本語特化モデルへの変更で精度が向上する場合があります。

```python
detector = UnknownDetector(
    resolved_logs=log_texts,
    log_ids=log_ids,
    model_name="intfloat/multilingual-e5-large",  # より高精度
)
```

モデルを変更した場合は必ずキャッシュを再生成してください（モデル名が一致しないとロード時にエラーが発生します）。

---

## テスト

```bash
pip install pytest
pytest tests
```

`tests/gen_test_syslog.py` で正解ラベル付きのテスト用 Syslog（5000 行、known / review / strong）を生成できます。

```bash
python tests/gen_test_syslog.py <出力先ディレクトリ>
```

---

## Reference

- Qiita: https://qiita.com/kkae1278
