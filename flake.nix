{
  description = "PWN Environment for nixpkgs 23.11 (pwndbg/pwntools/tmux)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";  # 明确使用23.11版本
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = {
            allowUnfree = true;
            glibcLocales.enable = true;  # 解决Locale问题
          };
        };

        # 核心工具集（23.11版本中pwndbg是独立包，非Python模块）
        pwnTools = with pkgs; [
          pwndbg                          # 独立的pwndbg包（23.11版本正确引用）
          glibcLocales                    # Locale支持
          netcat-openbsd                  # 网络调试
          vim                             # 编辑工具
          
          # Python工具（23.11版本中这些包存在）
          python311Packages.pwntools
          python311Packages.ropper
          python311Packages.ropgadget
          python311Packages.angr
          python311Packages.pygments      # pwndbg依赖
          python311Packages.six           # pwndbg依赖
        ];

        # 关键：手动指定pwndbg的Python模块路径（23.11版本的正确路径）
        pwndbgPythonDir = "${pkgs.pwndbg}/share/pwndbg";
      in {
        devShell = pkgs.mkShell {
          packages = pwnTools;

          shellHook = ''
            # 1. 解决Locale编码问题
            export LOCALE_ARCHIVE="${pkgs.glibcLocales}/lib/locale/locale-archive"
            export LC_ALL=en_US.UTF-8
            export PYTHONIOENCODING=UTF-8
            echo "[1/3] ✅ Locale配置完成"

            # 2. 配置Python路径（让Python找到pwndbg模块）
            export PYTHONPATH="$pwndbgPythonDir:$PYTHONPATH"
            echo "[2/3] ✅ Python路径配置完成（已添加pwndbg模块）"

            # 3. 配置.gdbinit（加载pwndbg+tmux分窗）
            GDBINIT_PATH="$HOME/.gdbinit"
            PWNDBG_GDBINIT="${pkgs.pwndbg}/share/pwndbg/gdbinit.py"

            if [ ! -f "$GDBINIT_PATH" ] || ! grep -q "$PWNDBG_GDBINIT" "$GDBINIT_PATH"; then
              echo "[3/3] ✅ 配置.gdbinit..."
              cat > "$GDBINIT_PATH" <<EOF
set disassembly-flavor intel
source $PWNDBG_GDBINIT
python
import atexit, os
from pwndbg.commands.context import contextoutput
bt = os.popen('tmux splitw -P -F "#{pane_id}:#{pane_tty}" -d cat').read().strip().split(":")
st = os.popen(f'tmux splitw -h -t {bt[0]} -P -F "#{pane_id}:#{pane_tty}" -d cat').read().strip().split(":")
regs = os.popen(f'tmux splitw -h -t {st[0]} -P -F "#{pane_id}:#{pane_tty}" -d cat').read().strip().split(":")
disasm = os.popen('tmux splitw -h -P -F "#{pane_id}:#{pane_tty}" -d cat').read().strip().split(":")
panes = {"backtrace": bt, "stack": st, "regs": regs, "disasm": disasm}
for name, info in panes.items():
    contextoutput(name, info[1], True)
contextoutput("legend", disasm[1], True)
atexit.register(lambda: [os.popen(f"tmux killp -t {p[0]}") for p in panes.values()])
end
EOF
            else
              echo "[3/3] ✅ .gdbinit已配置"
            fi

            # 验证环境
            echo -e "\n=== 环境验证 ==="
            python3 -c "import pwn" 2>/dev/null && echo "✅ pwntools" || echo "❌ pwntools"
            command -v pwndbg >/dev/null && echo "✅ pwndbg" || echo "❌ pwndbg"
            command -v tmux >/dev/null && echo "✅ tmux" || echo "❌ tmux"
            echo "================\n"
          '';
        };
      });
}
