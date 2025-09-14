{
  description = "PWN Development Environment with pwndbg and pwntools";

  # 使用固定版本的nixpkgs以确保环境一致性
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11"; # 使用稳定版本避免频繁更新
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          # 启用32位支持和非自由软件
          config = {
            allowUnfree = true;
            multilib.enable = true; # 支持32位程序调试
          };
        };

        # 核心PWN工具集
        pwnTools = with pkgs; [
          # 调试工具
          gdb
          pwndbg           # GDB插件，用于漏洞利用调试
          
          # 漏洞利用工具
          python311Packages.pwntools  # 核心漏洞利用库
          python311Packages.ropper    # ROP分析工具
          python311Packages.ropgadget # ROP Gadget搜索
          
        ];
      in {
        devShell = pkgs.mkShell {
          packages = pwnTools;

          # 环境初始化脚本
          shellHook = ''
            # 确保使用已缓存的工具链
            echo "使用缓存的PWN环境，路径: $out"

            # 验证关键工具是否可用
            echo "验证环境..."
            command -v gdb >/dev/null 2>&1 && echo "✓ gdb已安装" || echo "✗ gdb未安装"
            python3 -c "import pwn" >/dev/null 2>&1 && echo "✓ pwntools已安装" || echo "✗ pwntools未安装"
            
            echo "PWN环境准备就绪！"
          '';
        };
      });
}
