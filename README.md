# autologin-script

Windows se po startu přihlásí samy, bez hesla. Hodí se pro PC, které jen pouští jednu věc (VJ stanice, kiosek, server doma).

## Použití

| Chci | Spusť |
|---|---|
| zapnout autologin | `autologin.bat` |
| vypnout autologin | `undo.bat` |

Oba si samy řeknou o práva správce. Pak restartuj PC.

## Co skript dělá

1. Povolí prázdné heslo (minimální délka 0, bez složitosti).
2. Odstraní heslo přihlášeného uživatele.
3. Zapne automatické přihlášení v registru (`Winlogon`).

`undo.bat` vypne jen autologin. Heslo si pak nastav znovu přes **Ctrl+Alt+Del → Změnit heslo**.

Log: `%TEMP%\autologin.log`

## Upozornění

- **Jen pro lokální účet.** S účtem Microsoft (přihlášení e-mailem) to nefunguje.
- PC bez hesla odemkne každý, kdo k němu sedne. Na notebook, se kterým chodíš ven, to nedávej.
