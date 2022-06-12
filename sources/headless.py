from pyppeteer import launch, connect

from loguru import logger
import re
import time
import asyncio

class Handlers():
    def __init__(self, new_headers={}):
        self.new_headers = {k.lower(): v for k,v in new_headers.items()}

    def request_handler(self, request):
        # if request.url.endswith('.png') or request.url.endswith('.jpg'):
        #     await request.abort()
        asyncio.create_task(request.continue_())


class Response():
    def __init__(self, url, headers, status_code, text, time=0 ) -> None:
        self.url = url
        self.headers = headers
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8")
        self.elapsed = self.Elapsed(time)
    
    class Elapsed():
        def __init__(self, time=1) -> None:
            self.time = time
        def total_seconds(self):
            return self.time
        


class Web_headless():
    def __init__(self, forced_headers = {}, 
            timeout=30,
            redirects=False,
            independant_chrome=None,
            pyppeteer_args={"headless": True, "ignoreHTTPSErrors": True, "handleSIGTERM": False,"handleSIGHUP": False, "handleSIGINT": False, "executablePath": "/usr/bin/chromium-browser", "devtools": False, "args": ["--no-sandbox"]},):
            
        self.pyppeteer_args = pyppeteer_args
        self.pages = list()
        self.results = dict()
        self.forced_headers = forced_headers
        self.timeout = timeout
        self.redirects = redirects
        self.independant_chrome = independant_chrome
        self.Handlers = Handlers(new_headers=forced_headers)
        
    
    def rewrite_headers(self, headers):
        self.Handlers = Handlers(new_headers=headers)
    
    async def spawn_browser(self,):
        if self.independant_chrome is None:
            print("Spawning browser")
            return await launch(self.pyppeteer_args)
        else:
            print(f"Connecting to browser on port {self.independant_chrome}")
            return await connect(browserURL=f'http://127.0.0.1:{self.independant_chrome}')
    
    async def new_page(self, browser):
        if self.independant_chrome is None:
            page = await browser.newPage()
            await page.setRequestInterception(True)
            page.on('request', self.Handlers.request_handler)
        else:
            [page, *_] = await browser.pages()
            await page.setRequestInterception(False)
        
        await page.setViewport({'width': 1920, 'height': 1080})

        page.setDefaultNavigationTimeout(self.timeout * 1000)

        self.results.setdefault(0, dict())
        return page
    
    async def page_goto(self, page, url, headers:dict = {}):
        try:
            await page.setExtraHTTPHeaders(headers)
            time_bef = time.time()
            p = await page.goto(url, waitUntil="networkidle2", followRedirect=self.redirects)
            time_aft = time.time()
        except Exception as e:
            logger.error(f"Error: {e}")
            return Response(url, headers, 0, "", time=round(time.time()-time_bef, 4))
        self.results[0]["url"] = url
        response = Response(url, p.headers, p.status, await self.get_page_content(page), time=round(time_aft-time_bef, 4))
        return response
    
    async def get_page_content(self, page):
        body = await page.content()
        self.results[0]["body"] = body
        return body
    
    async def close_browser(self):
        await self.browser.close()
    
    async def screenshot_page(self, id, path):
        await self.pages[id].screenshot({'path': f"/tmp/{path}.png"})