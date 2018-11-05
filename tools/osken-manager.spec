# -*- mode: python -*-

block_cipher = None


a = Analysis(['../bin/osken-manager'],
             pathex=['../os_ken'],
             binaries=None,
             datas=None,
             hiddenimports=['os_ken.controller.ofp_handler'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
          cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='osken-manager',
          debug=False,
          strip=False,
          upx=True,
          console=True)
