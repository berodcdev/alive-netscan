"""Utilitários compartilhados dos testes."""

from __future__ import annotations

import io
import re

import pytest
from rich.console import Console

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def sem_ansi(texto: str) -> str:
    """Texto como o usuário lê, sem códigos de estilo."""
    return _ANSI.sub("", texto)


class Captura:
    """Console de largura fixa cuja leitura já vem sem ANSI.

    Ler a saída crua amarraria o teste à versão do rich: o que uma versão
    emite como estilo, outra emite de outro jeito — e a asserção quebra sem
    que uma letra da saída visível tenha mudado.
    """

    def __init__(self, width: int = 100) -> None:
        self._buf = io.StringIO()
        self.console = Console(
            file=self._buf, width=width, highlight=False, no_color=True,
            legacy_windows=False,
        )

    def getvalue(self) -> str:
        return sem_ansi(self._buf.getvalue())

    def linhas(self) -> list[str]:
        return self.getvalue().splitlines()


@pytest.fixture
def captura(monkeypatch):
    """Substitui o console do render por um capturável de 100 colunas."""
    from alive import render

    cap = Captura()
    monkeypatch.setattr(render, "console", cap.console)
    return cap
