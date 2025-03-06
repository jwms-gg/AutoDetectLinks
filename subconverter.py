import click
from pysubconverter import config_context, subconverter

import pathlib


def convert(input, output):
    with config_context():
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
def convert_folder_cmd(input):
    input = pathlib.Path(input).resolve()
    output = pathlib.Path(input).parent.joinpath("converted")
    output.mkdir(exist_ok=True)
    input_files = [
        f for f in input.iterdir() if f.is_file() and f.suffix in [".yaml", ".yml"]
    ]
    print(f"Converting {len(input_files)} files to clash format...")
    [convert(f, output.joinpath(f.name)) for f in input_files]


if __name__ == "__main__":
    entry_commands()
