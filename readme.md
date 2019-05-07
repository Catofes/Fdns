## Fdns

在国内使用无污染的dns，并且cdn返回正常地址。

### 目的

实现一个类似于tuna的dns。

如果直接使用隧道访问8.8.8.8，那么国内的cdn可能返回国外的节点（dns查询来源ip是国外的ip）。tuna的实现方式是通过透传使得xx无法发现dns请求包，自然也就无法污染，这样做到使用国内的ip请求dns结果。但是透传ip要求太高，这里用一个简单的方法达成类似的结果。

### 原理

前提：
	1. 被污染的结果一定是A记录。
	2. 被污染的结果的ip地址是国外段。

- 配置一组国内dns和国外dns
- 收到本地请求后同时向国内dns和国外dns发送请求
	- 国内dns回应国内ip，返回国内dns的结果
	- 国内dns回应国外ip，且等于国外dns结果，返回国内dns的结果
	- 国内dns回应国外ip，不等于国外dns结果，返回国外dns的结果

### 配置

```
{
		"ListenAddress": "127.0.0.1:53",
		"ChinaParents": ["114.114.114.114:53"],
		"OutSeaParents": ["101.6.6.6:53"],
		"IpDatabase": "./chnroutes.txt",
		"Debug": false
}
```
