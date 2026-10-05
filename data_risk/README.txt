ENDPOINT INVESTIGATOR - DATASET DE TREINAMENTO

Este dataset é sintético e foi criado para testar ferramentas de investigação de endpoints Linux.
Não representa um incidente real.

Nível: basic
Cenário: normal

Arquivos:
- processes.csv: snapshot de processos.
- permissions.csv: metadados de arquivos e diretórios.
- services.txt: serviços em execução.
- journal.log: eventos de sistema.
- metadata.json: metadados de geração.

Orientação: não assuma que um único indicador é suficiente para concluir que houve comprometimento.
Procure correlações e diferencie evidência, interpretação e hipótese.

Nota didática do cenário:
Há uma permissão excessivamente ampla em um arquivo, mas o dataset não estabelece que ele seja executado por um serviço privilegiado. O aluno deve diferenciar configuração inadequada de evidência de exploração.
