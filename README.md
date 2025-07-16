## libmagic 관련.

### macOS/Linux

현재 존재하는 uv.lock 및 pyproject.toml 파일 그대로 사용하면 됨.

### Windows

윈도우는 libmagic 이 정상적으로 링크되지 않으므로 아래 절차에 따라 윈도우용 라이브러리를 추가후 사용.

```sh
uv add python-magic-bin
```

## 실행방법

```sh
uv venv
uv sync
uv run main.py <directory>
```
