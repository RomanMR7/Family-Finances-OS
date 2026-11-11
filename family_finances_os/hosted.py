"""Public project page; never open personal databases on shared cloud workers."""
import http.server
import json
import os
import urllib.parse

HOSTED_HTML = '''<!doctype html><html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Family Finances OS — локальные семейные финансы</title>
<style>body{margin:0;background:#f5f4ee;color:#193f35;font:16px/1.65 system-ui,sans-serif}
main{max-width:760px;margin:9vh auto;padding:32px}small{letter-spacing:.12em;text-transform:uppercase}
h1{font-size:clamp(32px,7vw,54px);line-height:1.12;letter-spacing:-.04em}p{color:#50655e}
.notice{padding:20px 24px;border:1px solid #ccd7cd;border-radius:14px;background:#fffef9}
a{color:#17634e}a.button{display:inline-block;background:#205d49;color:#fff;padding:12px 20px;border-radius:9px;text-decoration:none;margin:14px 12px 0 0}
code{background:#e8ece3;padding:3px 7px;border-radius:5px}li{margin:10px 0}</style>
<main><small>Family Finances OS</small><h1>Финансы семьи.<br>На вашем устройстве.</h1>
<p>Локальное приложение для счетов, обязательных платежей, целей и расчётов. Финансовые данные остаются у семьи.</p>
<div class="notice"><strong>Этот сайт — страница проекта.</strong>
<p>Ввод финансовых данных, вход в базу и восстановление резервных копий здесь отключены.
Временная файловая система хостинга не используется для хранения семейной базы.</p></div>
<ol><li>Скачайте приложение из репозитория.</li><li>Установите зависимости: <code>python -m pip install -r requirements.txt</code>.</li>
<li>Запустите <code>python -m family_finances_os.web_server</code> и откройте адрес, указанный в терминале.</li></ol>
<a class="button" href="https://github.com/RomanMR7/Family-Finances-OS">Приложение и инструкция</a>
<a href="https://github.com/RomanMR7/Family-Finances-OS/archive/refs/heads/main.zip">Скачать ZIP</a>
<p>Сводные расчёты ведутся в RUB. Валютные счета показаны отдельно без неявного обмена.
Кредитные графики — оценка по указанным параметрам; условия договора проверяются отдельно.</p></main></html>'''


class handler(http.server.BaseHTTPRequestHandler):
    def _route(self):
        parsed=urllib.parse.urlparse(self.path)
        query=urllib.parse.parse_qs(parsed.query)
        return urllib.parse.urlparse(query.get('__url',[parsed.path])[0]).path

    def _reply(self,status,payload,content_type='application/json; charset=utf-8'):
        data=payload.encode('utf-8') if isinstance(payload,str) else json.dumps(payload,ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        headers={'Content-Type':content_type,'Content-Length':str(len(data)),'Cache-Control':'no-store',
                 'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer',
                 'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"}
        for key,value in headers.items():self.send_header(key,value)
        self.end_headers()
        if self.command!='HEAD':self.wfile.write(data)

    def do_GET(self):
        route=self._route()
        if route in ('/health','/api/health'):
            self._reply(200,{'status':'ok','mode':'local-server-required','finance_api_enabled':False,
                             'commit':os.environ.get('VERCEL_GIT_COMMIT_SHA')})
        elif route=='/':self._reply(200,HOSTED_HTML,'text/html; charset=utf-8')
        else:self._unavailable()

    def _unavailable(self):
        self._reply(503,{'status':'error','code':'LOCAL_SERVER_REQUIRED',
                          'message':'Финансовые данные на публичном хостинге не принимаются. Используйте локальное приложение.'})

    do_HEAD=do_GET
    do_POST=_unavailable
    do_PUT=_unavailable
    do_DELETE=_unavailable
