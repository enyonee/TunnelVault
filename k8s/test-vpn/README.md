# Integration Test Infrastructure

K8s namespace `test-vpn` с тремя VPN серверами для интеграционных тестов tunnelvault.

## VPN серверы

| Сервер | Порт | Протокол | Назначение |
|--------|------|----------|------------|
| openvpn-server | 1194/udp | OpenVPN | OpenVPN connect/disconnect/routing |
| ocserv | 4443/tcp | OpenConnect | FortiVPN (openfortivpn) connect/disconnect |
| singbox-server | 8388/tcp | Shadowsocks | sing-box tun mode |

## Деплой

```bash
kubectl apply -f namespace.yaml
kubectl apply -f openvpn-server.yaml
kubectl apply -f ocserv.yaml
kubectl apply -f singbox-server.yaml

# Дождаться готовности
kubectl wait --for=condition=Available deploy --all -n test-vpn --timeout=120s
```

## Запуск тестов

### В K8s (полный набор)

```bash
# Собрать образ test-runner
docker build -t ghcr.io/enyonee/tunnelvault-test:latest -f Dockerfile.test-runner ../..

# Запустить Job
kubectl apply -f test-runner-job.yaml
kubectl logs -f -n test-vpn job/tunnelvault-integration-test
```

### Локально (для разработки)

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

## Cleanup

```bash
kubectl delete namespace test-vpn
```
