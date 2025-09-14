{
  description = "PWN Development Environment with pwndbg, pwntools and tmux";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = {
            allowUnfree = true;
            multilib.enable = true;
          };
        };

        # 包含tmux的PWN工具集
        pwnTools = with pkgs; [
          # 调试工具
          gdb
          pwndbg
          
          # 漏洞利用工具
          python311Packages.pwntools
          python311Packages.ropper
          python311Packages.ropgadget
          python311Packages.angr
          
          # 辅助工具
          tmux  # 新增tmux支持
        ];
      in {
        devShell = pkgs.mkShell {
          packages = pwnTools;

          shellHook = ''
            echo "使用缓存的PWN环境，路径: $out"
            
            # 配置自定义.gdbinit文件
            GDBINIT_PATH="$HOME/.gdbinit"
            PWNDBG_PATH="${pkgs.pwndbg}/share/pwndbg/gdbinit.py"
            
            # 仅在.gdbinit不存在或内容不同时写入，避免重复操作
            if [ ! -f "$GDBINIT_PATH" ] || ! grep -q "tmux split-window" "$GDBINIT_PATH"; then
              echo "配置自定义.gdbinit文件..."
              cat > "$GDBINIT_PATH" <<EOF
set disassembly-flavor intel 
source $PWNDBG_PATH

python
import atexit
import os
from pwndbg.commands.context import contextoutput, output, clear_screen
bt = os.popen('tmux split-window -P -F "#{pane_id}:#{pane_tty}" -d "cat -"').read().strip().split(":")
st = os.popen(F'tmux split-window -h -t {bt[0]} -P -F '+'"#{pane_id}:#{pane_tty}" -d "cat -"').read().strip().split(":")
re = os.popen(F'tmux split-window -h -t {st[0]} -P -F '+'"#{pane_id}:#{pane_tty}" -d "cat -"').read().strip().split(":")
di = os.popen('tmux split-window -h -P -F "#{pane_id}:#{pane_tty}" -d "cat -"').read().strip().split(":")
panes = dict(backtrace=bt, stack=st, regs=re, disasm=di)
for sec, p in panes.items():
    contextoutput(sec, p[1], True)
contextoutput("legend", di[1], True)
atexit.register(lambda: [os.popen(F"tmux kill-pane -t {p[0]}").read() for p in panes.values()])
end
EOF
            fi

            # 设置32位程序运行环境
            export LD_LIBRARY_PATH="${pkgs.lib32.glibc}/lib:${pkgs.lib32.zlib}/lib:$LD_LIBRARY_PATH"
            
            # 验证关键工具是否可用
            echo "验证环境..."
            command -v tmux >/dev/null 2>&1 && echo "✓ tmux已安装" || echo "✗ tmux未安装"
            command -v gdb >/dev/null 2>&1 && echo "✓ gdb已安装" || echo "✗ gdb未安装"
            python3 -c "import pwn" >/dev/null 2>&1 && echo "✓ pwntools已安装" || echo "✗ pwntools未安装"
            
            echo "PWN环境准备就绪！使用tmux启动后运行gdb体验分窗调试"
          '';
        };
      });
}
