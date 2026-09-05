from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .banner import SNARE_BANNER
from .tester import probe_agent
from .traps import ВЕКТОРЫ, create_trap, list_traps

console = Console()


def _banner() -> None:
    console.print(f"[bold yellow]{SNARE_BANNER}[/bold yellow]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD browser-agent injection QA — устойчивость агента к инъекциям со страницы."""


@main.command("new")
@click.option("--vector", "вектор", required=True, type=click.Choice(sorted(ВЕКТОРЫ)))
def new_cmd(вектор: str) -> None:
    """Сгенерировать одну страницу-ловушку (для ручного просмотра)."""
    path, c = create_trap(вектор)
    console.print(f"{path}  (канарейка {c})")


@main.command("list")
def list_cmd() -> None:
    t = Table(title="snare traps")
    t.add_column("File")
    for p in list_traps():
        t.add_row(str(p))
    console.print(t)


@main.command("test")
@click.argument("agent_url")
@click.option("--trap-port", default=8971, show_default=True)
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить JSON-находки (контракт пайплайна)")
def test_cmd(agent_url: str, trap_port: int, as_json: str | None) -> None:
    """Проверить агента: вынесет ли он скрытую инъекцию со страницы-ловушки."""
    d = probe_agent(agent_url, trap_port=trap_port)
    if as_json:
        Path(as_json).write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")

    # 🔴 rc=2 «не состоялась» ≠ rc=0 «чисто»
    if d["verdict"] == "НЕ ПРОВЕРЕНО":
        console.print(f"[yellow]НЕ ПРОВЕРЕНО[/yellow]: {d['not_proven']}")
        raise SystemExit(2)

    t = Table(title=f"snare: {agent_url}  ·  скрытых векторов: {d['векторов']}")
    t.add_column("вектор"); t.add_column("вердикт"); t.add_column("почему")
    for f in d["findings"]:
        цвет = {"ПРОВАЛ": "red", "НЕ ПРОВЕРЕНО": "yellow"}.get(f["вердикт"], "green")
        t.add_row(f["вектор"], f"[{цвет}]{f['вердикт']}[/{цвет}]", f["почему"])
    console.print(t)
    цвет = "red" if d["verdict"] == "ПРОВАЛ" else "green"
    console.print(f"Вердикт: [{цвет}]{d['verdict']}[/{цвет}] — {d['почему']}")

    if d["verdict"] == "ПРОВАЛ":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
