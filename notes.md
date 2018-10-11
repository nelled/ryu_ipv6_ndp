* Steps for implementing
** First step should be inserting rule which forwards all relevant packets to controller
*** All NDP messages?? Can flow rule be installed which forwards only relevant types?

**** How to identify NDP messages? Read up on ipv6 and how to do it in ryu
**** Specific prefix or something similar? Install flow table entry which forwards all those packets to controller



* Email fragen:
** Alle NDP abfangen? Das wäre sink functionality
** Was dann? App soll source und sink sein. Bedeutet dass, dass app selber informationen über die netzwerkstruktur hält und basierend auf diesem wissen
** responses generiert?