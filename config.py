import json
import pathlib
from dynaconf import Dynaconf

CONFIG_PATH = pathlib.Path(__file__).resolve().parent

settings = Dynaconf(
    env_switcher="LAUNCH_ENV",
    settings_files=[
        CONFIG_PATH / "settings.yaml",
    ],
    environments=True,
    envvar_prefix="CONF",
    lowercase_read=True,
)


final_settings = json.dumps(
    settings.to_dict(),
    indent=4,
    ensure_ascii=False,
    sort_keys=False,
    separators=(",", ":"),
)

with open(".settings.json", "w") as f:
    f.write(final_settings)
