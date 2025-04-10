# ECDSA + Fips 204 + Fips 205

## Requisitos
- Ter o Maven instalado, teste com:
```bash
mvn -v
```

## Instruções

- Entre no diretório __signature_algorithms-comparision__

```bash
cd signature_algorithms-comparision
```

- Limpe e compile o projeto usando Maven, isso baixará a biblioteca Bouncy Castle, junto com as bibliotecas Maven.

```bash
mvn clean install
```
- Execute o projeto com.
```bash
mvn exec:java
```

### Resultados
- Verifique os resultados no diretório __signature_algorithms-comparision/results__
