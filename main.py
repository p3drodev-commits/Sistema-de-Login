"""SISTEMA DE LOGIN (tkinter)

- Cadastro: nome, mês/ano de nascimento, sexo (M/F) e senha.
- A senha é guardada criptografada (PBKDF2-HMAC-SHA256 + salt aleatório).
- O sistema gera um número de usuário aleatório com 6 dígitos.
- Após o cadastro, abre a tela de login com o número do usuário e a senha.
- A parte de senha (medidor e gerador) vem do arquivo main.py.
"""

import hashlib
import hmac
import json
import secrets
import string
import tkinter as tk
from datetime import date
from pathlib import Path
from tkinter import ttk, messagebox

ARQUIVO_USUARIOS = Path(__file__).with_name("usuarios.json")

# ---------------------------------------------------------------------------
# Parte de senha (aproveitada do main.py)
# ---------------------------------------------------------------------------
TAMANHO_MINIMO = 8
SIMBOLOS = "!@#$%&*()-_=+[]{};:,.<>?/"


def avaliar_senha(senha):
    """Retorna (classificação, pontos) da senha."""
    pontos = 0

    if len(senha) >= 8:
        pontos += 1
    if len(senha) >= 12:
        pontos += 1

    if any(c in string.ascii_lowercase for c in senha):
        pontos += 1
    if any(c in string.ascii_uppercase for c in senha):
        pontos += 1
    if any(c in string.digits for c in senha):
        pontos += 1
    if any(c in SIMBOLOS for c in senha):
        pontos += 1

    if pontos <= 3:
        return "Fraca", pontos
    elif pontos <= 5:
        return "Boa", pontos
    else:
        return "Forte", pontos


def gerar_senha(tamanho=12):
    """Gera uma senha aleatória com letras, números e símbolos."""
    if tamanho < TAMANHO_MINIMO:
        tamanho = TAMANHO_MINIMO

    senha = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(SIMBOLOS),
    ]
    todos = string.ascii_letters + string.digits + SIMBOLOS
    while len(senha) < tamanho:
        senha.append(secrets.choice(todos))

    secrets.SystemRandom().shuffle(senha)
    return "".join(senha)


# ---------------------------------------------------------------------------
# Criptografia e armazenamento
# ---------------------------------------------------------------------------
ITERACOES = 200_000


def criptografar_senha(senha, salt=None):
    """Retorna (salt_hex, hash_hex) usando PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, ITERACOES)
    return salt.hex(), h.hex()


def verificar_senha(senha, salt_hex, hash_hex):
    _, novo = criptografar_senha(senha, bytes.fromhex(salt_hex))
    return hmac.compare_digest(novo, hash_hex)


def carregar_usuarios():
    if ARQUIVO_USUARIOS.exists():
        try:
            return json.loads(ARQUIVO_USUARIOS.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def salvar_usuarios(usuarios):
    ARQUIVO_USUARIOS.write_text(
        json.dumps(usuarios, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def gerar_numero_usuario(usuarios):
    """Número aleatório de 6 dígitos (apenas números), único."""
    while True:
        numero = f"{secrets.randbelow(10**6):06d}"
        if numero not in usuarios:
            return numero


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sistema de Login")
        self.resizable(False, False)
        self.frame_atual = None
        self.mostrar_cadastro()

    def trocar_tela(self, frame):
        if self.frame_atual is not None:
            self.frame_atual.destroy()
        self.frame_atual = frame
        frame.pack(padx=24, pady=20)
        self.update_idletasks()
        # centraliza a janela
        w, h = self.winfo_reqwidth(), self.winfo_reqheight()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 3
        self.geometry(f"+{x}+{y}")

    def mostrar_cadastro(self):
        self.title("Cadastro")
        self.trocar_tela(TelaCadastro(self))

    def mostrar_login(self, numero="", senha="", novo_cadastro=False):
        self.title("Login")
        self.trocar_tela(TelaLogin(self, numero, senha, novo_cadastro))

    def mostrar_boas_vindas(self, numero, nome):
        self.title("Bem-vindo")
        self.trocar_tela(TelaBoasVindas(self, numero, nome))


class TelaCadastro(ttk.Frame):
    CORES = {"Fraca": "#c0392b", "Boa": "#d68910", "Forte": "#1e8449"}

    def __init__(self, app):
        super().__init__()
        self.app = app

        ttk.Label(self, text="Cadastro de Usuário", font=("Segoe UI", 15, "bold")).grid(
            row=0, column=0, columnspan=3, pady=(0, 14)
        )

        # Nome
        ttk.Label(self, text="Nome:").grid(row=1, column=0, sticky="w", pady=4)
        self.var_nome = tk.StringVar()
        ttk.Entry(self, textvariable=self.var_nome, width=32).grid(
            row=1, column=1, columnspan=2, sticky="we"
        )

        # Nascimento (mês e ano)
        ttk.Label(self, text="Nascimento:").grid(row=2, column=0, sticky="w", pady=4)
        frame_nasc = ttk.Frame(self)
        frame_nasc.grid(row=2, column=1, columnspan=2, sticky="w")
        self.var_mes = tk.StringVar()
        self.var_ano = tk.StringVar()
        ttk.Combobox(
            frame_nasc, textvariable=self.var_mes, width=5, state="readonly",
            values=[f"{m:02d}" for m in range(1, 13)],
        ).pack(side="left")
        ttk.Label(frame_nasc, text=" / ").pack(side="left")
        ano_atual = date.today().year
        ttk.Combobox(
            frame_nasc, textvariable=self.var_ano, width=7, state="readonly",
            values=[str(a) for a in range(ano_atual, 1899, -1)],
        ).pack(side="left")
        ttk.Label(frame_nasc, text="  (mês / ano)").pack(side="left")

        # Sexo
        ttk.Label(self, text="Sexo:").grid(row=3, column=0, sticky="w", pady=4)
        frame_sexo = ttk.Frame(self)
        frame_sexo.grid(row=3, column=1, columnspan=2, sticky="w")
        self.var_sexo = tk.StringVar()
        ttk.Radiobutton(frame_sexo, text="M", variable=self.var_sexo, value="M").pack(side="left")
        ttk.Radiobutton(frame_sexo, text="F", variable=self.var_sexo, value="F").pack(
            side="left", padx=(12, 0)
        )

        # Senha
        ttk.Label(self, text="Senha:").grid(row=4, column=0, sticky="w", pady=4)
        self.var_senha = tk.StringVar()
        self.entry_senha = ttk.Entry(self, textvariable=self.var_senha, show="*", width=32)
        self.entry_senha.grid(row=4, column=1, columnspan=2, sticky="we")
        self.var_senha.trace_add("write", lambda *_: self.atualizar_medidor())

        self.var_mostrar = tk.BooleanVar()
        ttk.Checkbutton(
            self, text="Mostrar senha", variable=self.var_mostrar,
            command=lambda: self.entry_senha.config(show="" if self.var_mostrar.get() else "*"),
        ).grid(row=5, column=1, sticky="w")
        ttk.Button(self, text="Gerar senha aleatória", command=self.gerar).grid(
            row=5, column=2, sticky="e"
        )

        # Medidor
        self.lbl_medidor = ttk.Label(self, text=f"Mínimo de {TAMANHO_MINIMO} caracteres")
        self.lbl_medidor.grid(row=6, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self.barra = ttk.Progressbar(self, maximum=6, length=300)
        self.barra.grid(row=7, column=0, columnspan=3, sticky="we", pady=(2, 12))

        # Botões
        ttk.Button(self, text="Cadastrar", command=self.cadastrar).grid(
            row=8, column=0, columnspan=2, sticky="we", padx=(0, 6)
        )
        ttk.Button(self, text="Já tenho conta", command=lambda: app.mostrar_login()).grid(
            row=8, column=2, sticky="we"
        )

    def gerar(self):
        self.var_senha.set(gerar_senha(12))
        self.var_mostrar.set(True)
        self.entry_senha.config(show="")

    def atualizar_medidor(self):
        senha = self.var_senha.get()
        if not senha:
            self.lbl_medidor.config(text=f"Mínimo de {TAMANHO_MINIMO} caracteres", foreground="")
            self.barra["value"] = 0
            return
        classificacao, pontos = avaliar_senha(senha)
        self.lbl_medidor.config(
            text=f"Medidor de segurança: {classificacao} ({pontos}/6 pontos)",
            foreground=self.CORES[classificacao],
        )
        self.barra["value"] = pontos

    def cadastrar(self):
        nome = self.var_nome.get().strip()
        mes, ano = self.var_mes.get(), self.var_ano.get()
        sexo = self.var_sexo.get()
        senha = self.var_senha.get()

        if len(nome) < 2:
            return messagebox.showwarning("Cadastro", "Informe o seu nome.")
        if not mes or not ano:
            return messagebox.showwarning("Cadastro", "Selecione o mês e o ano de nascimento.")
        hoje = date.today()
        if (int(ano), int(mes)) > (hoje.year, hoje.month):
            return messagebox.showwarning("Cadastro", "A data de nascimento está no futuro.")
        if sexo not in ("M", "F"):
            return messagebox.showwarning("Cadastro", "Selecione o sexo (M ou F).")
        if len(senha) < TAMANHO_MINIMO:
            return messagebox.showwarning(
                "Cadastro", f"Senha muito curta! Use pelo menos {TAMANHO_MINIMO} caracteres."
            )

        usuarios = carregar_usuarios()
        numero = gerar_numero_usuario(usuarios)
        salt, hash_senha = criptografar_senha(senha)
        usuarios[numero] = {
            "nome": nome,
            "nascimento": f"{mes}/{ano}",
            "sexo": sexo,
            "salt": salt,
            "senha_hash": hash_senha,
        }
        try:
            salvar_usuarios(usuarios)
        except OSError as e:
            return messagebox.showerror("Cadastro", f"Não foi possível salvar o cadastro:\n{e}")

        # Vai para a tela de login mostrando número do usuário e senha
        self.app.mostrar_login(numero, senha, novo_cadastro=True)


class TelaLogin(ttk.Frame):
    def __init__(self, app, numero="", senha="", novo_cadastro=False):
        super().__init__()
        self.app = app

        ttk.Label(self, text="Login", font=("Segoe UI", 15, "bold")).grid(
            row=0, column=0, columnspan=2, pady=(0, 10)
        )

        if novo_cadastro:
            ttk.Label(
                self,
                text=f"Cadastro concluído!\nSeu número de usuário é: {numero}\nGuarde-o para entrar.",
                justify="center", foreground="#1e8449",
            ).grid(row=1, column=0, columnspan=2, pady=(0, 10))

        ttk.Label(self, text="Número do usuário:").grid(row=2, column=0, sticky="w", pady=4)
        self.var_numero = tk.StringVar(value=numero)
        ttk.Entry(self, textvariable=self.var_numero, width=24).grid(row=2, column=1)

        ttk.Label(self, text="Senha:").grid(row=3, column=0, sticky="w", pady=4)
        self.var_senha = tk.StringVar(value=senha)
        self.entry_senha = ttk.Entry(self, textvariable=self.var_senha, show="*", width=24)
        self.entry_senha.grid(row=3, column=1)

        self.var_mostrar = tk.BooleanVar()
        ttk.Checkbutton(
            self, text="Mostrar senha", variable=self.var_mostrar,
            command=lambda: self.entry_senha.config(show="" if self.var_mostrar.get() else "*"),
        ).grid(row=4, column=1, sticky="w")

        ttk.Button(self, text="Entrar", command=self.entrar).grid(
            row=5, column=0, columnspan=2, sticky="we", pady=(12, 4)
        )
        ttk.Button(self, text="Novo cadastro", command=app.mostrar_cadastro).grid(
            row=6, column=0, columnspan=2, sticky="we"
        )
        self.entry_senha.bind("<Return>", lambda _e: self.entrar())

    def entrar(self):
        numero = self.var_numero.get().strip()
        senha = self.var_senha.get()
        usuario = carregar_usuarios().get(numero)

        if usuario and verificar_senha(senha, usuario["salt"], usuario["senha_hash"]):
            self.app.mostrar_boas_vindas(numero, usuario["nome"])
        else:
            messagebox.showerror("Login", "Número do usuário ou senha incorretos.")


class TelaBoasVindas(ttk.Frame):
    def __init__(self, app, numero, nome):
        super().__init__()
        ttk.Label(self, text=f"Bem-vindo(a), {nome}!", font=("Segoe UI", 15, "bold")).pack(pady=(0, 6))
        ttk.Label(self, text=f"Usuário nº {numero}").pack(pady=(0, 14))
        ttk.Button(self, text="Sair", command=app.mostrar_login).pack(fill="x")


if __name__ == "__main__":
    App().mainloop()