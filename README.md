# 广播攻击

## 题目附件

```python
from Crypto.Util.number import *
import os

flag = os.getenv('FLAG')
m = bytes_to_long(flag.encode())
e = 127

def enc():
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    c = pow(m, e, n)
    print(f"n: {n}")
    print(f"c: {c}")

def main():
    while True:
        opt = int(input('input> '))
        if opt == 1:
            enc()

main()
```

这个题目是一个 nc 交互题。输入 `1` 后，会返回一组 `n` 和 `c`。整体可以分为两个部分：

1. nc 交互获取多组数据
2. 广播攻击核心恢复思路

## 核心解题思路

先取 3 组样例数据：

```text
n1 =70844145380729121689042179671798733881975329856761939850171752214823212246819254325085137523878838518683033486321140227564195821302470530087298175180779444846735655805185383888454159481670053851137632425200706587102387363498091099168844742773157191513054556569633400401836921550623390278705902041689110628821
c1 =39377557129230727331588492964128705313365217735794107700022103774211600867964055418333428743450465576975381733419385246472201501289956353670502547893054521741083727113137880753972968308414646985751514893276199015704408639367429204858772444283716022166480015468762528236678841923434863415407096045428958200104

n2 =104661596971729125609664258071225101020901182352881021435283223313361149923035006105660951920227284897624330191260013324092215299042837083191330316682595017058617742766260572441602301402032303173578154206734148898468443309695082495748636535931931663677696921827743890264879554581651729546858628147274513669423
c2 =52201025883492290928072490395999196214244709544941261790925153003812278762067495185462224994894251408010283429336786117173672349595411486994806941575001044727554731633048817689219991055145211130781041824473253604936377910160563108876708194964220125756515332220992925726544025195546700629851687175750317940351

n3 =160052091746750258656931530936337101822651205964654375395268842062518806679785546572535030895643797832480239353681805541497458614613079714911961444355640405823071959997481914694149355383698738729483372311724190558913687059151889524221341892049588622681521612731548573660764940041062640546023864845618929295021
c3 =52201025883492290928072490395999196214244709544941261790925153003812278762067495185462224994894251408010283429336786117173672349595411486994806941575001044727554731633048817689219991055145211130781041824473253604936377910160563108876708194964220125756515332220992925726544025195546700629851687175750317940351
```

对于每一组数据，都满足：

$$
m^e \equiv c_i \pmod{n_i}
$$

也就是说同一个明文对应的 $m^e$ 对每个 $n_i$ 取模后都能回到对应的 $c_i$。

等价写法是：

$$
c_i \equiv m^e \pmod{n_i}
$$

现在构造单项式 $T_i$：

$$
T_i = c_i \cdot M_i \cdot y_i
$$

其中：

- $N = \prod_{j=1}^{k} n_j$
- $M_i = \dfrac{N}{n_i}$
- $y_i$ 是 $M_i$ 在模 $n_i$ 下的逆元，即：

$$
M_i y_i \equiv 1 \pmod{n_i}
$$

于是可得：

- 当验证第 $i$ 组时，$T_i \equiv c_i \pmod{n_i}$
- 对于其他组，因 $M_i$ 含对应模因子，贡献在该模下为 $0$

最后把所有 $T_i$ 相加：

$$
X = \sum_{i=1}^{k} c_i M_i y_i
$$

则有：

$$
X \equiv c_i \pmod{n_i}, \quad i = 1,2,\dots,k
$$

因此可由中国剩余定理重构出 $m^e$，再开 $e$ 次方恢复 $m$。另外要保证收集到的组数至少满足攻击需求（通常需足够多组，且模数条件满足）。

后面就是代码验证。

```python
T = 0
N = 1
for i in n_list:
    N *= i

# 求 T
for i in range(len(c_list)):
    M = N // n_list[i]
    y = gmpy2.invert(M, n_list[i])
    T += (M * y * c_list[i]) % N
    T = T % N

print(T)
m = iroot(T, e)
print(m[1])
print(long_to_bytes(m[0]))
```

## 终端交互

```python
import gmpy2
from gmpy2 import iroot
from pwn import *
import re

from Crypto.Util.number import long_to_bytes

n_list = []
c_list = []
e = 127

io = remote('', )
for i in range(e):
    io.recvuntil(b"input>")
    io.sendline(b"1")
    io.recvline()
    data = io.recvline()
    data += io.recvline()
    data_str = data.decode()

    n = re.search(r'n[:=]\s*(\d+)', data_str)
    c = re.search(r'c[:=]\s*(\d+)', data_str)
    if n and c:
        n_list.append(int(n.group(1)))
        c_list.append(int(c.group(1)))

io.close()

print(len(n_list))
print(len(c_list))
```

整合版如下：

```python
import gmpy2
from gmpy2 import iroot
from pwn import *
import re

from Crypto.Util.number import long_to_bytes

n_list = []
c_list = []
e = 127

io = remote('10.10.70.220', 60271)
for i in range(e):
    io.recvuntil(b"input>")
    io.sendline(b"1")
    io.recvline()
    data = io.recvline()
    data += io.recvline()
    data_str = data.decode()

    n = re.search(r'n[:=]\s*(\d+)', data_str)
    c = re.search(r'c[:=]\s*(\d+)', data_str)
    if n and c:
        n_list.append(int(n.group(1)))
        c_list.append(int(c.group(1)))

io.close()

print(len(n_list))
print(len(c_list))

T = 0
N = 1
for i in n_list:
    N *= i

# 求 T
for i in range(len(c_list)):
    M = N // n_list[i]
    y = gmpy2.invert(M, n_list[i])
    T += (M * y * c_list[i]) % N
    T = T % N

print(T)
m = iroot(T, e)
print(m[1])
print(long_to_bytes(m[0]))
```
