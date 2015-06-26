  1. 采用TAB缩进。
  1. 编辑器中每个TAB设为8个字符长。
  1. 原则上每行不超过80个字符，头文件可以酌情考虑。
  1. 指针星号紧贴变量名称。
```
char *pa, *pb;
```
  1. 头文件函数名对齐。
```
int   foo();
void  bar();  
char *get_string();
```

  1. 长表达式超过80个字符要换行，新的一行多缩进一个TAB，行首以运算符开始。
```
int a = foo_1() + foo_2() + foo_3() + ...
	+ foo_n();
```
  1. 数据结构和函数的命名尽量遵从依赖的基础库的命名规范。
> OpenSSL风格

```
typedef struct object_st {
	int a;
	int b;
} OBJECT;
int OBJECT_foo_bar();
```
> Linux/GMP风格

```
typedef struct object_t {
	int a;
	int b;
} object_t;
int object_foo_bar();
```

  1. 数据结构内部元素的排版。如果数据结构内部有少量属性，在数据类型和变量之间采用单个空格。
```
typedef struct foo_t {
	int a;
	char *b;
	unsigned long c;
	unsigned char d[40];
} foo_t;
```
> 如果数据结构作包含多项内容，并作为暴露给调用者的接口，采用如下方式：
```
typedef struct foo_t {
	int            a;
	char          *b;
	unsigned long  c;
	unsigned short d[40];
} foo_t;
```
> 注意数据类型和变量名称之间全部由空格填充，不包含TAB。

  1. 函数内部变量的定义放在函数的最开始，按类型分组，尽量按出现的先后顺序排列。
  1. 如果一个函数会生成不经过自己释放的动态内存，函数名中必须标明 new/init，并且提供对应的 free/cleanup 接口。
```
BIGNUM *BN_new();
BN_free(BIGNUM *);
	
BIGNUM bn;
int BN_init(&bn);
BN_cleanup(&bn);
```

  1. 运算符前后要空白字符。
```
int c = a + b;
```
> 而不是
int c=a+b;

  1. 函数最外侧括号独占一行。
```
int add(int a, int b)
{
	int c = a + b;
	return c;
}
```

  1. if, while, for 的括号写法
```
if (a > b) {
	foo();
	bar();
} else {
	bar();
	foo();
}

if (a > b)
	foo();
else
	bar();


while (1) {
	foo();
	bar();
}

for (;;) {
	foo();
	bar();
}
```

  1. 代码结构、变量名称和算法、标准保持一致，尽量不要注释。
  1. 注释的写法
> 单行注释
```
/* this is comment */
```
> 多行注释
```
/* 
  * This is the comment.
  * Another line.
  * The last line.
  */
```
> 注销代码
```
#if 0
int c = 3 + 6;
#endif
```

  1. FIXME和TODO
> 有问题的地方要标准
```
/* FIXME: error or reason */
/* TODO: or what to do */
```

  1. 命名可以采用常见的单词缩写减少变量和函数名称的长度
```
ctx		context
param		parameter
buf		buffer
```

如果一组函数中采用了常用缩写，需要在代码中保持一致。
函数接口中尽量给全称，而在函数的内部实现中可以更多采用缩写。

  1. 文件名
文件名字符只包含小写字母、数字以及下划线，不可包含大写字母，减号以及其他字符。
文件名尽量简短。
```
sha1.h
sha1.c
sha1test.c
sha1cmd.c
sha1_init.c
sha1_update.c
sha1_final.c
```

一个源文件尽量控制在1000行以内，如果c文件内容太多，可以按照模块化的方式切分为多个源文件。

  1. 可移植性。C语言具有良好的可移植性，不要在代码中包含固定的路径字符串，不要直接将数据结构、整型变量直接采用memcpy的方式写入文件或网络。

  1. 宏的命名
  * 尽量少用宏。
**宏的定义要用括号阔起来。** 不要将宏作为开放接口暴露给调用者。
