# shell.nix - 100% 复刻主机环境

# 直接导入您主机上正在使用的 nixpkgs 版本
{ pkgs ? import /nix/var/nix/profiles/per-user/root/channels/nixpkgs {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # 使用与主机完全相同的 pwndbg 包
    pwndbg
    
    # 如果需要其他工具，可以在这里添加
    # radare2
    # strace
    # ltrace
  ];

  shellHook = ''
    echo "🚀 进入 PWN 环境"
    echo "📦 使用的 nixpkgs: /nix/var/nix/profiles/per-user/root/channels/nixpkgs"
    echo "💡 'gdb' 命令已预装 pwndbg"
  '';
}