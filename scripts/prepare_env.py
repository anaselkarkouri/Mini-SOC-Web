"""Créer un fichier privé neuf; refuse d'écraser les identifiants existants."""
import argparse, os, secrets, subprocess
from pathlib import Path
parser=argparse.ArgumentParser()
parser.add_argument('--php',default='php')
parser.add_argument('--directory',type=Path,default=Path('.'))
args=parser.parse_args()
destination=args.directory/'.env'
if destination.exists(): raise SystemExit('.env existe déjà; aucune modification.')
values={f'MINISOC_{role}_PASSWORD':secrets.token_hex(24) for role in ('ROOT','WEB','COLLECTOR','SIEM','SOC')}
login=secrets.token_hex(16)
result=subprocess.run([args.php,'-r',"echo password_hash(trim(fgets(STDIN)), PASSWORD_BCRYPT);"],
                       input=login+'\n',text=True,capture_output=True,check=True)
values['MINISOC_SOC_PASSWORD_HASH']=result.stdout.strip()
values['MINISOC_RUN_UID']=str(os.getuid() if hasattr(os,'getuid') else 1000)
values['MINISOC_RUN_GID']=str(os.getgid() if hasattr(os,'getgid') else 1000)
destination.write_text('\n'.join(k+"='"+v+"'" for k,v in values.items())+'\n',encoding='utf-8')
private=args.directory/'runtime';private.mkdir(exist_ok=True)
(private/'soc-login.private').write_text(login+'\n',encoding='utf-8')
(private/'zap').mkdir(exist_ok=True)
if os.name!='nt':
    destination.chmod(0o600);(private/'soc-login.private').chmod(0o600)
print('Configuration privée créée; mot de passe SOC dans runtime/soc-login.private.')
