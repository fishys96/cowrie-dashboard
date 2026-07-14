from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    cowrie_log_path: str = "/var/log/cowrie/cowrie.json"

    geoip_city_db: str = "./geoip/GeoLite2-City.mmdb"
    geoip_asn_db: str = "./geoip/GeoLite2-ASN.mmdb"

    honeypot_lat: float = 37.3719
    honeypot_lon: float = -79.8164
    honeypot_label: str = "Azure VPS"

    host: str = "127.0.0.1"
    port: int = 8080

    db_path: str = "./data/dashboard.db"

    feed_limit: int = 200
    poll_interval: float = 0.5
    timeline_hours: int = 24
    replay_on_start: bool = True


settings = Settings()

Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
