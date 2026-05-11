# Netword-Discovery-Toolkit
 é uma ferramenta gráfica profissional para descoberta de rede, identificação inteligente de dispositivos e geolocalização. Desenvolvida com Python e Tkinter, foi projetada para profissionais de TI e segurança que precisam mapear e entender suas redes de forma rápida e ética.

> "Seu canivete suíço para inventário de rede."

##  Funcionalidades Principais

- **Descoberta de Rede Multi-Thread**: Varre redes /24 em segundos, com barra de progresso e opção de parada.
- **Identificação Inteligente**: Utiliza **banco de dados de MAC Address (OUI próprio)** com +80 fabricantes! Consegue identificar roteadores, smartphones, notebooks, servidores, Smart TVs, Raspberry Pi, dispositivos IoT e mais.
- **Escaneamento de Portas (Opcional)**: Detecta portas comuns (21, 22, 80, 443, etc.) para ajudar a classificar o tipo do dispositivo.
- **Geolocalização de IPs**: Descubra o país, cidade e ISP de qualquer IP público usando uma API externa (com sistema de cache interno).
- **Relatórios Detalhados**: Gere relatórios em texto ou exporte todos os dados em JSON para análises posteriores.
- **Interface Gráfica Intuitiva**: Design escuro profissional com abas organizadas (Rede, Dispositivos, Geolocalização, Relatórios, Logs).
- **Informações Detalhadas**: Dê duplo clique em qualquer dispositivo para abrir uma janela com todas as informações, incluindo geolocalização e portas abertas.

##  Para que Serve?

Esta ferramenta foi criada para **fins educacionais e auditoria de redes autorizadas** (como a sua própria rede doméstica ou de trabalho). Com ela você pode:
- Manter um inventário atualizado de todos os dispositivos da sua rede.
- Identificar rapidamente dispositivos desconhecidos ou não autorizados.
- Estudar na prática conceitos de rede como ARP, ICMP, DNS e TCP/IP.

##  Como Executar (Uso Rápido)

### Pré-requisitos
- **Python 3.8+** instalado.
- Permissões de **Administrador**. (Necessário para acessar a tabela ARP e descobrir os endereços MAC).

