# Como lançar uma versão

A versão é fonte única em `alive/__init__.py` (`__version__`). O `pyproject.toml`
a lê de lá, e o CI confere que a tag bate com ela.

## 1. Preparar

1. Atualize `__version__` em `alive/__init__.py`.
2. Adicione a seção da versão no topo de `CHANGELOG.md`.
3. Rode o portão local:
   ```bash
   pytest -q && ruff check . && python -m build && twine check dist/*
   ```

## 2. Publicar no PyPI (automático)

O push de uma tag `vX.Y.Z` dispara `.github/workflows/publish.yml`, que faz o
build, confere que a tag bate com `__version__` e publica no PyPI.

```bash
git commit -am "release: vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main --tags
```

**Pré-requisito, só uma vez:** registrar o Trusted Publisher no PyPI em
`https://pypi.org/manage/project/alive-netscan/settings/publishing/`
(owner `berodcdev`, repo `alive-netscan`, workflow `publish.yml`, environment
`pypi`). Assim nenhum token fica no repositório. Para o primeiríssimo upload,
como o projeto ainda não existe no PyPI, use o formulário de "pending publisher"
em `https://pypi.org/manage/account/publishing/`.

Instalação pelo usuário final depois disso:

```bash
pipx install alive-netscan     # recomendado (ambiente isolado)
pip install --user alive-netscan
```

## 3. Atualizar o AUR

O `PKGBUILD` fica em `packaging/aur/`. A cada versão:

```bash
cd packaging/aur
sed -i "s/^pkgver=.*/pkgver=X.Y.Z/" PKGBUILD
updpkgsums                       # baixa o tarball da tag e fixa o sha256
makepkg -si                      # testa build e instalação localmente
makepkg --printsrcinfo > .SRCINFO
```

Depois, no repositório do AUR (`ssh://aur@aur.archlinux.org/alive-netscan.git`,
precisa de conta AUR e chave SSH cadastrada):

```bash
git commit -am "upgpkg: alive-netscan X.Y.Z"
git push
```
