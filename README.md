# Esqueleto de Projeto SGX

Este ficheiro ZIP contém apenas a **estrutura base** necessária para desenvolver aplicações com Intel SGX no âmbito da unidade curricular Cibersegurança do ISEL. Inclui a organização das pastas, a *Makefile* e os ficheiros de configuração essenciais, permitindo que os alunos comecem os seus projetos sem terem de configurar tudo de raiz.

Recomenda-se a utilização deste esqueleto para o desenvolvimento de aplicações SGX em Cibersegurança.

---

## Estrutura das pastas

```text
.
├── readme.md
├── Makefile
├── application/
│   ├── src/        # Guarda os ficheiros .c da aplicação (código não confiável)
│   ├── inc/        # Guarda os ficheiros .h da aplicação
│   ├── obj/        # Guarda os ficheiros gerados automaticamente (ficheiros objeto)
│   └── bin/        # Guarda o ficheiro executável gerado automaticamente (app e enclave.signed.so)
└── enclave/
    ├── src/        # Guarda os ficheiros .c que implementam o enclave (código confiável)
    ├── inc/        # Guarda os ficheiros .h do enclave
    ├── conf/       # Guarda os ficheiros de interface e configuração do enclave (EDL, XML, LDS, chave)
    ├── obj/        # Guarda os ficheiros gerados automaticamente (ficheiros objeto)
    └── bin/        # Guarda a biblioteca gerada automaticamente (enclave.so)
```
Os nomes dos binários podem ser alterados editando as variáveis `APP_NAME`, `ENCLAVE_NAME` e `SIGNED_ENCLAVE_NAME` no topo da *Makefile*.

Os ficheiros na diretoria **conf/** já estão preparados para uso imediato:

- `enclave.edl` - define ECALL/OCALL
- `enclave.config.xml` - configurações do enclave
- `enclave.lds` - linker script
- `enclave_private_test.pem` - chave de assinatura para desenvolvimento

**Atenção**: As pastas `obj/` e `bin/` são geradas automaticamente e não devem ser editadas manualmente.

---

## Compilação

Antes de compilar a sua aplicação, carregue o ambiente SGX SDK usando o seguinte comando num terminal da máquina virtual:

```bash
source /opt/sgxsdk/environment
```

Depois, execute o comando na diretoria base do projeto (onde está o ficheiro *Makefile*):

```bash
make
```

Outros modos de compilação opcionais:

```bash
make SGX_DEBUG=0                 # release (simulação)
make SGX_PRERELEASE=1 SGX_DEBUG=0
```

---

## Executar a aplicação

Pode executar a aplicação usando o seguinte comando na diretoria base do projeto (onde está o ficheiro *Makefile*):

```bash
make run
```

---


## Limpar o projeto

Para remover todos os ficheiros gerados pela *Makefile* use o comando:

```bash
make clean
```

---

## Explicação do Código

### 1. Visão Geral do Projeto
O objetivo desta aplicação é gerar números inteiros aleatórios de forma segura e verificar se são números primos. Tanto a geração quanto a verificação ocorrem dentro de um **Enclave**, garantindo que a geração de números aleatórios seja confiável e que a computação esteja isolada do resto do sistema.

### 2. A Interface (`enclave/conf/enclave.edl`)
O ficheiro **EDL (Enclave Definition Language)** define o contrato entre a aplicação não confiável e o enclave confiável.

```c
trusted {
    public int get_random_int(void);
    public int is_prime(int n);
};
```
*   **bloco `trusted`**: Define **ECALLs** (Enclave Calls). Estas são funções que a aplicação não confiável pode chamar para executar código *dentro* do enclave.
*   **`get_random_int`**: Pede ao enclave para gerar um número aleatório.
*   **`is_prime`**: Pede ao enclave para verificar se um número específico `n` é primo.

### 3. A Aplicação Host (`application/src/app.c`)
Esta é a parte "não confiável" do código que corre no ambiente normal do SO.

*   **Inicialização**: Chama `sgx_create_enclave` para carregar a imagem assinada do enclave (`enclave.signed.so`) para a memória protegida.
*   **O Loop**:
    1.  Chama `get_random_int(global_eid, &n)` para obter um número. Note que, embora a função C retorne `int`, a função proxy SGX recebe um ponteiro `&n` para armazenar o valor de retorno.
    2.  Chama `is_prime(global_eid, &p, n)` para verificar o número.
    3.  Imprime o resultado na consola.
    4.  O loop repete-se `do ... while( p != 1 )` até que um número primo seja encontrado.
*   **Limpeza**: Finalmente, liberta os recursos com `sgx_destroy_enclave`.

### 4. O Enclave (`enclave/src/enclave.c`)
Este é o código "confiável" que corre dentro da área de memória protegida.

*   **`get_random_int`**:
    *   Usa `sgx_read_rand`, uma função especial SGX que usa o gerador de números aleatórios por hardware do CPU (instrução RDRAND) para gerar bytes aleatórios criptograficamente seguros.
    *   Garante que o número é positivo (`val < 0 ? -val : val`).
*   **`is_prime`**:
    *   Implementa um algoritmo matemático padrão para verificar a primalidade.
    *   Trata casos extremos (<= 1, números pares) e depois realiza divisões sucessivas até à raiz quadrada de `n`.

