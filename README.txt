Segurança e Confiabilidade
O TrokosPay é um sistema cliente-servidor desenvolvido em Java que oferece uma plataforma segura e confiável para gerenciamento de pagamentos entre usuários. O sistema permite a realização de transferências diretas, criação de pedidos de pagamento (individuais e por QR Code), e a organização de pagamentos em grupo com histórico e status detalhado.

Além das funcionalidades básicas de consulta de saldo e envio/recebimento de valores, o TrokosPay foca na colaboração entre usuários, suportando grupos de pagamento compartilhado com rastreamento individual de contribuições. Os dados são persistidos em arquivos de texto para fácil verificação e debugging.

Como compilar:
Servidor: javac src\server\TrokosServer.java
Cliente: javac src\client\TrokosClient.java

Testar:
Após o código compilado
O jar foi criado através do eclipse

Pelo Jar:
Servidor: java -jar Server.jar <port>
Cliente: java -jar Client.jar <serverAddress> <userID> [password]

Métodos:
----------------------------------------------------
• balance – obtém valor atual do saldo da sua conta
----------------------------------------------------
• makepayment <userID> <amount> – se o userID nao existir ou o nao houver dinheiro suficiente na conta ,o cliente é notificado que nao houve pagamento
----------------------------------------------------
• requestpayment <userID> <amount> – se o userID nao existir o pedido nao é efetuado.
----------------------------------------------------
• viewrequests – obtém do servidor a sua lista de pedidos de pagamentos pendentes. Cada pedido é composto por um identificador único 
atribuído pelo sistema, pelo valor, e pela identificação do utilizador que fez o pedido.
----------------------------------------------------
• payrequest <reqID> – autoriza o pagamento do pedido com identificador reqID,
removendo o pedido da lista de pagamentos pendentes. Se o cliente não tiver saldo
suficiente na conta, deve ser retornado um erro. Se o identificador não existir ou se for
referente a um pagamento pedido a outro cliente, também deve retornar um erro.
----------------------------------------------------
• obtainQRcode <amount> – cria um pedido de pagamento no servidor e coloca-o numa
lista de pagamentos identificados por QR code. Cada pedido tem um QR code único no
sistema, e está associado ao clientID que criou o pedido (a quem o pagamento será feito),
e ao valor amount a ser pago. O servidor deverá devolver uma imagem com o QR code.
----------------------------------------------------
• confirmQRcode <QRcode> – confirma e autoriza o pagamento identificado por QR code,
removendo o pedido da lista mantida pelo servidor. Se o cliente não tiver saldo suficiente
na conta, deve ser retornado um erro (mas o pedido continua a ser removido da lista). Se
o pedido identificado por QR code não existir também deve retornar um erro.
----------------------------------------------------
• newgroup <groupID> – cria um grupo para pagamentos partilhados, cujo dono (owner)
será o cliente que o criou. Se o grupo já existir assinala um erro.
----------------------------------------------------
• addu <userID> <groupID> – adiciona o utilizador userID como membro do grupo indicado.
Se userID já pertencer ao grupo ou se o grupo não existir deve ser assinalado um erro.
Apenas os donos dos grupos podem adicionar utilizadores aos seus grupos, pelo que
deverá ser assinalado um erro caso o cliente não seja dono do grupo.
----------------------------------------------------
• groups – mostra uma lista dos grupos de que o cliente é dono, e uma lista dos grupos a
que pertence. Caso não seja dono de nenhum grupo ou não seja membro de nenhum
grupo, esses factos deverão ser assinalados.
----------------------------------------------------
• dividepayment <groupID> <amount> – cria um pedido de pagamento de grupo, cujo valor
total amount deve ser dividido pelos membros do grupo groupID. O pedido deve dar
origem a pedidos individuais a serem colocados na lista de pedidos pendentes de cada
membro do grupo. Quando todos os pedidos individuais forem pagos, o pedido de grupo
pode ser movido para um histórico de pedidos de grupo. Caso não seja dono do grupo ou
o grupo não exista, deve ser assinalado um erro.
----------------------------------------------------
• statuspayments <groupID> – mostra o estado de cada pedido de pagamento de grupo, ou
seja, que membros de grupo ainda não pagaram esse pedido. Caso não seja dono do grupo
ou o grupo não exista, deve ser assinalado um erro.
----------------------------------------------------
• history <groupID> mostra o histórico dos pagamentos do grupo groupID já concluídos.
Caso não seja dono do grupo ou o grupo não exista, deve ser assinalado um erro
----------------------------------------------------

Este trabalho contém:
•um ficheiro para os utilizadores (Users.txt), com os utilizadores do sistema e respetivas passwords (<userID>:<password>)
•um ficheiro para o balanço das contas de cada utilizador (Balance.txt),  com os utilizadores do sistema e respetivos saldos (<userID>:<saldo>)
•um ficheiro para guardar os grupos (Grupos.txt), com o id do grupo, o owner e os respetivos membros (<grupoID>:<owner>:<membro>:<membro>...)
•um ficheiro para guardar os pedidos individuais e os qrcodes (PedidosInd.txt), 
		com o id do pedido, o destinatario, o remetente , o valor (<reqID>:<destinatario>:<remetente>:<valor>), para pedidos individuais
		com o id do QRcode, o criador, o valor(<QRcode>:<criador>:<valor>), para QRcodes
			
•um ficheiro para guardar os pedidos de grupos (PedidosGrup.txt), com o id do pedidod de grupo, o id do grupo e os respetivos membros e se ja pagou ou nao (<reqGrupoID>:<grupoID>:<owner>:<membro>:<pago>:<membro>:<pago>...)
•um ficheiro para o historico dos pedidos de grupo(Historico.txt), com os pedidos de grupo (<reqGrupoID>:<grupoID>:<owner>:<membro>:<pago>:<membro>:<pago>...)
•ficheiros png que são gerados apos a execucao da funcao obtainQRCode, que contêm os qr codes gerados

Limitações de implementação:
•Foi encontrado um problema na execucao do problema que causa pagamentos mal sucedidos, mais especificamente retira-los
do ficheiro "PedidosInd.txt". Nao conseguimos chegar a origem deste problema devido ao facto de que na maioria das vezes
os pedidos e pagamentos sao realizados com sucesso
