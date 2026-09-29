"""Generator de loguri de autentificare Windows SINTETICE (Event ID 4624 și 4625).

Toate datele sunt inventate de acest script. Nu există loguri reale, nume reale sau adrese IP reale:
adresele externe ale atacatorilor sunt din intervalele rezervate pentru documentație (RFC 5737),
iar cele interne sunt din 10.0.0.0/16.

Ce simulează:
  * trafic normal: utilizatori care se loghează în timpul zilei (4624), cu rare greșeli de parolă (4625);
  * brute-force: un IP extern încearcă multe parole pentru UN singur utilizator;
  * password spraying: un IP extern încearcă puține parole pentru MULȚI utilizatori;
  * cazuri „greu de deosebit" care NU sunt atacuri: un utilizator care își blochează contul din greșeli
    repetate, și un serviciu configurat greșit care eșuează la fiecare câteva secunde.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

# probabilitatea logărilor pe ore (mai multe în timpul programului de lucru)
_HOUR_WEIGHTS = np.array(
    [0.2, 0.1, 0.1, 0.1, 0.1, 0.3, 1, 3, 8, 9, 9, 8, 6, 8, 9, 9, 8, 5, 2, 1, 0.6, 0.4, 0.3, 0.2],
    dtype=float,
)
_HOUR_P = _HOUR_WEIGHTS / _HOUR_WEIGHTS.sum()


@dataclass
class Config:
    seed: int = 42
    days: int = 7
    n_users: int = 80
    n_hosts: int = 12
    logins_per_user_per_day: float = 45.0
    typo_rate: float = 0.03          # ponderea logărilor normale care încep cu o parolă greșită
    n_bruteforce: int = 6
    n_spray: int = 4
    n_lockouts: int = 5              # utilizatori legitimi care greșesc parola de mai multe ori
    n_misconfigured_services: int = 2
    start: str = "2026-01-05 00:00:00"


def _users(n: int) -> list[str]:
    return [f"user{i:03d}" for i in range(n)]


def _ts(base: np.datetime64, seconds: np.ndarray) -> np.ndarray:
    return base + np.asarray(seconds).astype("timedelta64[s]")


def _frame(ts, event_id, user, src_ip, host, attack_type) -> pd.DataFrame:
    n = len(ts)
    return pd.DataFrame(
        {
            "timestamp": pd.to_datetime(ts),
            "event_id": np.full(n, event_id) if np.isscalar(event_id) else event_id,
            "user": user,
            "src_ip": src_ip,
            "host": host,
            "attack_type": attack_type,
        }
    )


def _normal_traffic(rng, cfg: Config, base, users, hosts) -> pd.DataFrame:
    parts = []
    for idx, user in enumerate(users):
        home_ip = f"10.0.{idx // 250}.{idx % 250 + 1}"
        k = rng.poisson(cfg.logins_per_user_per_day * cfg.days)
        day = rng.integers(0, cfg.days, k)
        hour = rng.choice(24, size=k, p=_HOUR_P)
        sec = rng.integers(0, 3600, k)
        t = day * 86400 + hour * 3600 + sec
        host = rng.choice(hosts, size=k)
        typo = rng.random(k) < cfg.typo_rate
        # o greșeală izolată de parolă (4625), urmată la câteva secunde de o autentificare reușită
        parts.append(_frame(_ts(base, t), 4624, user, home_ip, host, "none"))
        if typo.any():
            t_bad = t[typo] - rng.integers(3, 30, typo.sum())
            parts.append(_frame(_ts(base, t_bad), 4625, user, home_ip, host[typo], "none"))
    return pd.concat(parts, ignore_index=True)


def _bruteforce(rng, cfg: Config, base, users, hosts, i: int) -> pd.DataFrame:
    ip = f"203.0.113.{10 + i}"
    target = rng.choice(users)
    host = rng.choice(hosts)
    start = rng.integers(0, cfg.days * 86400 - 600)
    n = int(rng.integers(40, 200))
    duration = rng.integers(60, 240)
    t = start + np.sort(rng.integers(0, duration, n))
    parts = [_frame(_ts(base, t), 4625, target, ip, host, "brute_force")]
    if rng.random() < 0.5:  # uneori atacatorul nimerește parola
        parts.append(_frame(_ts(base, [t[-1] + 5]), 4624, target, ip, host, "brute_force"))
    return pd.concat(parts, ignore_index=True)


def _spray(rng, cfg: Config, base, users, hosts, i: int) -> pd.DataFrame:
    ip = f"198.51.100.{10 + i}"
    m = min(int(rng.integers(15, 30)), len(users))
    victims = rng.choice(users, size=m, replace=False)
    start = rng.integers(0, cfg.days * 86400 - 1200)
    span = int(rng.integers(300, 900))
    parts = []
    for v in victims:
        tries = int(rng.integers(1, 4))
        t = start + rng.integers(0, span, tries)
        parts.append(_frame(_ts(base, t), 4625, v, ip, rng.choice(hosts), "password_spray"))
    return pd.concat(parts, ignore_index=True)


def _lockout(rng, cfg: Config, base, users, hosts, idx: int) -> pd.DataFrame:
    """Utilizator legitim care greșește parola de 6-9 ori, apoi reușește. NU este atac."""
    u = int(rng.integers(0, len(users)))
    ip = f"10.0.{u // 250}.{u % 250 + 1}"
    start = rng.integers(0, cfg.days * 86400 - 600)
    n = int(rng.integers(6, 10))
    t = start + np.sort(rng.integers(0, 180, n))
    parts = [
        _frame(_ts(base, t), 4625, users[u], ip, rng.choice(hosts), "none"),
        _frame(_ts(base, [t[-1] + 8]), 4624, users[u], ip, rng.choice(hosts), "none"),
    ]
    return pd.concat(parts, ignore_index=True)


def _misconfigured_service(rng, cfg: Config, base, hosts, i: int) -> pd.DataFrame:
    """Un serviciu cu parolă veche care eșuează la fiecare 20-30 s timp de ~20 min. NU este atac."""
    ip = f"10.0.200.{i + 1}"
    start = rng.integers(0, cfg.days * 86400 - 1500)
    t = start + np.cumsum(rng.integers(20, 31, 45))
    return _frame(_ts(base, t), 4625, "svc_backup", ip, rng.choice(hosts), "none")


def generate_events(cfg: Config | None = None) -> pd.DataFrame:
    """Returnează un tabel cu evenimente sintetice, sortat în timp.

    Coloane: timestamp, event_id (4624/4625), user, src_ip, host, attack_type
    (`none`, `brute_force` sau `password_spray`; folosită DOAR pentru evaluare, nu ca intrare a modelului).
    """
    cfg = cfg or Config()
    rng = np.random.default_rng(cfg.seed)
    base = np.datetime64(cfg.start, "s")
    users = _users(cfg.n_users)
    hosts = [f"HOST-{i:02d}" for i in range(cfg.n_hosts)]

    parts = [_normal_traffic(rng, cfg, base, users, hosts)]
    parts += [_bruteforce(rng, cfg, base, users, hosts, i) for i in range(cfg.n_bruteforce)]
    parts += [_spray(rng, cfg, base, users, hosts, i) for i in range(cfg.n_spray)]
    parts += [_lockout(rng, cfg, base, users, hosts, i) for i in range(cfg.n_lockouts)]
    parts += [_misconfigured_service(rng, cfg, base, hosts, i) for i in range(cfg.n_misconfigured_services)]
    events = pd.concat(parts, ignore_index=True)
    return events.sort_values("timestamp", kind="stable").reset_index(drop=True)
