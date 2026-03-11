# Integration Test Infrastructure

Ephemeral K8s namespace с VPN серверами для интеграционных тестов tunnelvault.

## Принципы

- **Ephemeral** - namespace создаётся на время тестов и удаляется после
- **Isolated** - NetworkPolicy блокирует доступ к prod/shared namespaces
- **Resource-limited** - ResourceQuota: max 2 CPU, 2Gi RAM, 10 pods, 0 PVCs

## VPN серверы

| Сервер | Порт | Протокол | Назначение |
|--------|------|----------|------------|
| openvpn-server | 1194/udp | OpenVPN | OpenVPN connect/disconnect/routing |
| ocserv | 4443/tcp | OpenConnect | FortiVPN (openfortivpn) connect/disconnect |
| singbox-server | 8388/tcp | Shadowsocks | sing-box tun mode |

## Запуск (ephemeral)

```bash
# Один скрипт: создаёт namespace, деплоит серверы, запускает тесты, удаляет namespace
./run-tests.sh

# Оставить namespace после тестов (для отладки)
./run-tests.sh --keep
```

## Запуск (ручной)

```bash
# Создать namespace с политиками
kubectl apply -f namespace.yaml
kubectl apply -f network-policy.yaml
kubectl apply -f resource-quota.yaml

# Деплой VPN серверов
kubectl apply -f openvpn-server.yaml
kubectl apply -f ocserv.yaml
kubectl apply -f singbox-server.yaml

# Собрать и запустить тесты
docker build -t ghcr.io/enyonee/tunnelvault-test:latest -f Dockerfile.test-runner ../..
kubectl apply -f test-runner-job.yaml
kubectl logs -f -n test-vpn job/tunnelvault-integration-test
```

## Локально (для разработки)

```bash
# Пробросить порты VPN серверов
kubectl port-forward -n test-vpn svc/openvpn-server 1194:1194 &
kubectl port-forward -n test-vpn svc/ocserv 4443:4443 &
kubectl port-forward -n test-vpn svc/singbox-server 8388:8388 &

# Запустить тесты
OPENVPN_SERVER=localhost \
OCSERV_HOST=localhost OCSERV_PORT=4443 OCSERV_USER=testuser OCSERV_PASS=testpass \
SINGBOX_SERVER=localhost SINGBOX_SS_PORT=8388 SINGBOX_SS_PASSWORD=test-password-12345 \
sudo -E uv run pytest tests/integration/k8s/ -x -v --tb=short
```

## Безопасность

- **NetworkPolicy**: test pods не могут достучаться до pod/service CIDR других namespaces (10.42.0.0/16, 10.43.0.0/16). Интернет разрешён.
- **ResourceQuota**: max 1 CPU requests, 2 CPU limits, 2Gi memory, 10 pods, 0 PVCs (только emptyDir)
- **LimitRange**: дефолтные лимиты 200m CPU / 256Mi RAM на контейнер
- **No ArgoCD**: test namespaces не управляются ArgoCD
