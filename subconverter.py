import click
from pysubconverter import config_context, subconverter, settings

import pathlib


def convert(input, output):
    settings.pref_path = str(
        pathlib.Path(__file__).parent / "subconverter" / "config" / "pref.toml"
    )
    with config_context(
        cache_dir=str(pathlib.Path(__file__).parent.joinpath("subconverter"))
    ):
        result = subconverter(
            {
                "target": "clash",
                "url": str(input),
            }
        )
        with open(output, "w", encoding="utf-8") as f:
            f.write(result.replace("!<str> ", ""))


entry_commands = click.Group(
    name="subconverter cli commands",
)


@entry_commands.command("converter")
@click.option(
    "-i", "--input", type=click.Path(exists=True), required=True, help="Input file path"
)
@click.option(
    "-o", "--output", type=click.Path(), required=True, help="Output file path"
)
def convert_cmd(input, output):
    output = pathlib.Path(output).resolve()
    input = pathlib.Path(input).resolve()
    convert(input, output)


@entry_commands.command("folder")
@click.option(
    "-i",
    "--input",
    type=click.Path(exists=True),
    required=True,
    help="Input folder path",
)
@click.option(
    "-o", "--output", type=click.Path(), required=True, help="Output folder path"
)
def convert_folder_cmd(input, output):
    input = pathlib.Path(input).resolve()
    output = pathlib.Path(output).resolve()
    output.mkdir(exist_ok=True)
    input_files = [
        f for f in input.iterdir() if f.is_file() and f.suffix in [".yaml", ".yml"]
    ]
    print(f"Converting {len(input_files)} files to ${output} folder...")
    [convert(f, output.joinpath(f.name)) for f in input_files]


if __name__ == "__main__":
    entry_commands()
