# scoring api
> This script realizes simple api example


### Usage
Run `api.py` to run webserver on port `8080` by default

```bash
Usage: api.py [options]

Options:
  -h, --help            show this help message and exit
  -p PORT, --port=PORT
  -l LOG, --log=LOG
```

### Query examples
Getting online score:

`{"account": "horns&hoofs", "login": "admin", "method": "online_score", "arguments": {"phone": "79999999999", "email": "example@mail.ru"}}`

Getting clients interests:

`{"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "arguments": {"client_ids": [1, 2], "date": "19.07.2017"}}`
