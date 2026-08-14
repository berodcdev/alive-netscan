# VHS tape — gera o GIF de demonstração do alive.
# Requer: vhs (https://github.com/charmbracelet/vhs). Rode:  vhs assets/demo.tape
# Usa `alive --demo` (dados fictícios) — nenhuma rede real é exposta.

Output assets/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1240
Set Height 1010
Set Padding 24
Set TypingSpeed 55ms
Set Theme { "name": "alive-matrix", "background": "#0a0d0a", "foreground": "#c8e6c9", "black": "#0a0d0a", "red": "#ff5f5f", "green": "#39ff14", "yellow": "#f4f465", "blue": "#5fafff", "magenta": "#d787ff", "cyan": "#5fffd7", "white": "#e8f5e9", "brightBlack": "#5c6d5c", "brightRed": "#ff8787", "brightGreen": "#8bff6b", "brightYellow": "#ffff87", "brightBlue": "#87d7ff", "brightMagenta": "#ffafff", "brightCyan": "#afffff", "brightWhite": "#ffffff", "cursor": "#39ff14", "selection": "#1f3d1f" }

# Prepara o PATH sem aparecer no GIF.
Hide
Type "export PATH=$HOME/.local/bin:$PATH; clear"
Enter
Show

Sleep 800ms
Type "alive --demo"
Sleep 700ms
Enter
Sleep 6s

Type "# use apenas em redes autorizadas ;)"
Sleep 2s
