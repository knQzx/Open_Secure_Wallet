from cryptography.fernet import Fernet

address = 'http://localhost:8080'
database_address = 'sqlite:///tables_data.db'
secret_key = 'hkDX13YB^!@@62r37fFDF@DFUDEN*#26eq6^E@%&W!E^DFF&E%@'
main_key = b'pnnnlbk75PnuFXhjTkT7NFUR5_ACoT2aohjic8V6Yr0='
main_key = Fernet(main_key)
