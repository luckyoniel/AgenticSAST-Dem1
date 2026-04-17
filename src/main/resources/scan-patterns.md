SEC-001|硬编码密钥/敏感信息 [违反 PCI-DSS Req 8]|(?i)(password|passwd|pwd|secret|api_key|aws_access_key_id)\s*=\s*["'][^"']+["']
FIN-001|潜在敏感持卡人数据流转(未脱敏) [参考 PCI-DSS Req 3]|(?i)(cardNumber|cvv|idCard|mobile)
AUTH-001|访问控制失效(水平/垂直越权) [违反 PCI-DSS Req 6.5]|(?i)(userId|accountId|orderId)
