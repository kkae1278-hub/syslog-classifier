"""
テスト用 Syslog 5000 行を生成する（正解ラベル付き）。

  known  : 台帳(_create_sample_ledger) と同じ事象。ホスト名・書式・変数を変えている
  review : 台帳の事象と意味は近いが言い回しが異なる
  strong : 台帳に存在しない事象（Linux/FW/ストレージ/日本語メッセージ等）

出力:
  syslog_test_5000.log   : 1行1ログ（コメント行・空行も混ぜてローダーを検証）
  syslog_test_5000.xlsx  : 「今週のSyslog」シート
  syslog_test_5000_labels.csv : 行ごとの正解ラベル
"""
import csv
import random
import sys
from datetime import datetime, timedelta

import pandas as pd

N = 5000
rng = random.Random(20261020)

hosts = ([f"core-sw{i:02d}" for i in range(1, 9)] + [f"edge-rt{i:02d}" for i in range(1, 5)]
         + [f"sw{i:02d}" for i in range(1, 16)] + ["fw01", "fw02", "srv-web01", "srv-db01"])
users = ["admin", "operator", "noc-user", "root", "sysadmin", "backup", "tanaka", "suzuki"]


def ip():
    return f"{rng.choice([10, 172, 192])}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def ipv6():
    return "2001:db8:" + ":".join(f"{rng.randint(0, 0xffff):x}" for _ in range(3)) + "::" + f"{rng.randint(1, 0xff):x}"


def mac():
    return ":".join(f"{rng.randint(0,255):02x}" for _ in range(6))


def gi():
    return f"GigabitEthernet{rng.randint(0,3)}/{rng.randint(0,47)}"


def r(a, b):
    return rng.randint(a, b)


h = lambda: rng.choice(hosts)
u = lambda: rng.choice(users)

# ── known: 台帳 26 テンプレートと同じ文面 ─────────────────────────
KNOWN = [
    lambda: f"{h()} Link down on {gi()}",
    lambda: f"{h()} Interface {gi()} changed state to down",
    lambda: f"{h()} Interface FastEthernet{r(0,3)}/{r(0,24)} is up, line protocol is up",
    lambda: f"{h()} {gi()}: duplex mismatch detected",
    lambda: f"{h()} Line protocol on Interface {gi()} changed state to up",
    lambda: f"{h()} BGP session with {ip()} reset by peer",
    lambda: f"{h()} BGP-5-ADJCHANGE: neighbor {ip()} Down BGP Notification sent",
    lambda: f"{h()} OSPF-5-ADJCHG: Nbr {ip()} on {gi()} from FULL to DOWN",
    lambda: f"{h()} BGP session with {ip()} established",
    lambda: f"{h()} OSPF neighbor {ip()} is up on {gi()}",
    lambda: f"{h()} Authentication failed for user {u()} from {ip()}",
    lambda: f"{h()} SSH: User {u()} authenticated from {ip()}",
    lambda: f"{h()} User {u()} login failed {r(3,12)} times, account locked",
    lambda: f"{h()} Failed password for {u()} from {ip()} port {r(1024,65535)} ssh2",
    lambda: f"{h()} Accepted publickey for {u()} from {ip()}",
    lambda: f"{h()} CPU utilization exceeded {r(70,99)} percent threshold",
    lambda: f"{h()} Memory utilization at {r(70,99)}%, threshold exceeded",
    lambda: f"{h()} High CPU usage detected: {r(70,99)}% for process snmpd",
    lambda: f"{h()} Fan failure detected in slot {r(1,8)}",
    lambda: f"{h()} Temperature sensor {r(1,6)} exceeded threshold: {r(45,85)} degrees Celsius",
    lambda: f"{h()} Power supply unit {r(1,4)} failed",
    lambda: f"{h()} Disk usage at {r(80,99)}%, threshold exceeded",
    lambda: f"{h()} STP: Topology change detected on VLAN {r(1,4094)}",
    lambda: f"{h()} VLAN {r(1,4094)} state changed to active",
    lambda: f"{h()} DHCP pool {r(1,20)} exhausted",
    lambda: f"{h()} NTP: synchronization lost",
]

# ── review: 既知事象の言い換え ────────────────────────────────────
REVIEW = [
    lambda: f"{h()} Port {gi()} transitioned to down state due to loss of signal",
    lambda: f"{h()} BGP peer {ip()} connection closed, hold timer expired",
    lambda: f"{h()} Invalid credentials supplied by user {u()} from {ip()}",
    lambda: f"{h()} Cooling fan {r(1,6)} stopped spinning",
    lambda: f"{h()} Chassis temperature too high: {r(60,90)}C on sensor {r(1,4)}",
    lambda: f"{h()} Free memory dropped below {r(5,15)}% of total",
    lambda: f"{h()} Processor load is very high at {r(85,100)}%",
    lambda: f"{h()} PSU {r(1,2)} lost input power, running on redundant supply",
    lambda: f"{h()} Filesystem /var is {r(90,99)}% full",
    lambda: f"{h()} Time source {ip()} unreachable, clock is unsynchronized",
    lambda: f"{h()} No free addresses left in DHCP scope {r(1,20)}",
    lambda: f"{h()} Spanning tree root bridge changed on VLAN {r(1,4094)}",
    lambda: f"{h()} OSPF adjacency with {ip()} lost on {gi()}",
    lambda: f"{h()} Too many failed SSH logins for {u()}, user disabled",
]

# ── strong: 台帳にない事象 ───────────────────────────────────────
STRONG = [
    lambda: f"{h()} kernel[{r(1,9)}]: Out of memory: Killed process {r(1000,65000)} (java) total-vm:{r(1000000,9000000)}kB",
    lambda: f"{h()} systemd[1]: nginx.service: Main process exited, code=exited, status=1/FAILURE",
    lambda: f"{h()} kernel[0]: EXT4-fs error (device sda{r(1,4)}): ext4_find_entry:1455: inode #{r(1000,99999)}: comm cron: reading directory lblock 0",
    lambda: f"{h()} SSL certificate for vpn.example.co.jp expires in {r(1,14)} days",
    lambda: f"{h()} %ASA-4-106023: Deny tcp src outside:{ip()}/{r(1024,65535)} dst inside:{ip()}/445 by access-group \"OUTSIDE_IN\"",
    lambda: f"{h()} IPSec tunnel to peer {ip()} failed phase 1 negotiation: no proposal chosen",
    lambda: f"{h()} RAID controller: virtual disk {r(0,3)} degraded, physical disk {r(0,7)} missing",
    lambda: f"{h()} %SW_MATM-4-MACFLAP_NOTIF: Host {mac()} in vlan {r(1,4094)} is flapping between port {gi()} and port {gi()}",
    lambda: f"{h()} IPv6 duplicate address {ipv6()} detected on {gi()}",
    lambda: f"{h()} Backup job DAILY-FULL failed: tape drive not ready",
    lambda: f"{h()} Configuration change by {u()} via vty0: 'no ip route 0.0.0.0 0.0.0.0 {ip()}'",
    lambda: f"{h()} ライセンスの有効期限が切れました。機能が制限されます",
    lambda: f"{h()} UPS がバッテリー運転に切り替わりました（残り {r(5,60)} 分）",
    lambda: f"{h()} DNS query flood detected from {ip()}: {r(5000,90000)} qps",
    lambda: f"{h()} Firmware upgrade aborted: image checksum mismatch 0x{r(0, 0xffffffff):08x}",
]

PRI = {"known": 189, "review": 187, "strong": 186}


def fmt(label, body):
    dt = datetime(2026, 10, 13) + timedelta(seconds=r(0, 7 * 86400 - 1))
    style = rng.random()
    if style < 0.55:          # ISO（台帳と同じ形式）
        return f"{dt:%Y-%m-%d %H:%M:%S} {body}"
    if style < 0.85:          # RFC3164 (BSD syslog)
        return f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S} {body}"
    if style < 0.95:          # ISO8601 'T' 区切り + タイムゾーン
        return f"{dt:%Y-%m-%dT%H:%M:%S}+09:00 {body}"
    return f"<{PRI[label]}>{dt:%b} {dt.day:>2} {dt:%H:%M:%S} {body}"  # PRI 付き


def main(outdir="."):
    n_known, n_review = int(N * 0.60), int(N * 0.20)
    n_strong = N - n_known - n_review
    rows = []
    for label, tmpls, n in (("known", KNOWN, n_known), ("review", REVIEW, n_review), ("strong", STRONG, n_strong)):
        for _ in range(n):
            tid = rng.randrange(len(tmpls))
            rows.append((label, f"{label}-{tid:02d}", fmt(label, tmpls[tid]())))
    rng.shuffle(rows)

    with open(f"{outdir}/syslog_test_5000.log", "w", encoding="utf-8", newline="\n") as f:
        f.write("# test syslog generated for syslog_classifier\n\n")
        for i, (_, _, line) in enumerate(rows):
            f.write(line + "\n")
            if i % 1000 == 999:
                f.write("\n# ---- chunk boundary ----\n")
    with open(f"{outdir}/syslog_test_5000_labels.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["idx", "label", "template", "raw"])
        for i, (lab, tid, line) in enumerate(rows):
            w.writerow([i, lab, tid, line])
    pd.DataFrame({"ログ本文（raw）": [x[2] for x in rows]}).to_excel(
        f"{outdir}/syslog_test_5000.xlsx", sheet_name="今週のSyslog", index=False)
    print(f"generated {len(rows)} lines (known={n_known}, review={n_review}, strong={n_strong})")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
