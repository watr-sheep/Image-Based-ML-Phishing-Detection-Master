import re
import mechanize as mechanize
from bs4 import BeautifulSoup
import socket
import requests
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from tqdm import tqdm
from urllib.parse import urljoin, urlparse
import io
import pytesseract
from PIL import Image
import http.cookiejar


def diff_month(d1, d2):
    return (d1.year - d2.year) * 12 + d1.month - d2.month

def main(url):
    parsed = urlparse(url)
    url_valid = bool(parsed.netloc) and bool(parsed.scheme)

    if url_valid:

        data_row = []

        if not re.match(r"^https?", url):
            url = "http://" + url

        try:
            response = requests.get(url, timeout=1)
            soup = BeautifulSoup(response.text, 'html.parser')

        except:
            response = ""
            soup = -999

        domain = re.findall(r"://([^/]+)/?", url)[0]

        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")

        try:

            whois_response = whois.whois(domain)
            whois_resp_check = 1

        except:
            print("whois error")
            whois_resp_check = 0

        rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {
            "name": domain
        })

        try:
            global_rank = int(re.findall(
                r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
        except:
            global_rank = -1

        # 1.Containing IP address on URL

        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
        if match:
            data_row.append(1)
            print('1 OK')

        else:
            data_row.append(-1)
            print('1 OK')



        # 2.Length of the URL
        if len(url) < 54:
            data_row.append(-1)
            print('2 OK')

        elif len(url) >= 54 and len(url) <= 75:
            data_row.append(0)
            print('2 OK')

        else:
            data_row.append(1)
            print('2 OK')


        # 3.Usage of Shortening Services
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',
                          url)
        if match:
            data_row.append(1)
            print('3 OK')

        else:
            data_row.append(-1)
            print('3 OK')


        # 4.Containing At symbol on URL
        if re.findall("@", url):
            data_row.append(1)
            print('4 OK')

        else:
            data_row.append(-1)
            print('4 OK')


        # 5.Check Double Slash Redirection
        list = [x.start(0) for x in re.finditer('//', url)]
        if list[len(list) - 1] > 6:
            data_row.append(1)
            print('5 OK')

        else:
            data_row.append(-1)
            print('5 OK')


        # 6.Containing Prefixes or Suffixes
        if re.findall(r"https?://[^\-]+-[^\-]+/", url):
            data_row.append(1)
            print('6 OK')

        else:
            data_row.append(-1)
            print('6 OK')


        # 7.having multiple sub domains
        if len(re.findall("\.", url)) == 1:
            data_row.append(-1)
            print('7 OK')

        elif len(re.findall("\.", url)) == 2:
            data_row.append(0)
            print('7 OK')

        else:
            data_row.append(1)
            print('7 OK')


        # 8.Check SSL State
        try:
            resp_txt = response.text
            if resp_txt:
                data_row.append(-1)
                print('8 OK')
            else:
                data_row.append(1)
                print('8 OK')
        except:
            data_row.append(1)
            print('8 OK')

        # 9.Domain Registration Check
        if response == "" or whois_resp_check == 0:
            data_row.append(1)
            print('9 OK')

        else:
            expiration_date = whois_response.expiration_date
            registration_length = 0
            try:
                expiration_date = min(expiration_date)
                today = time.strftime('%Y-%m-%d')
                today = datetime.strptime(today, '%Y-%m-%d')
                registration_length = abs((expiration_date - today).days)

                if registration_length / 365 <= 1:
                    data_row.append(1)
                    print('9 OK')

                else:
                    data_row.append(-1)
                    print('9 OK')

            except:
                data_row.append(1)
                print('9 OK')


        # 10.Usage of Favicons
        if soup == -999 or soup.text == "" or soup.text == '404: Not Found\n':
            data_row.append(1)
            print('10 OK')

        else:
            try:
                soup_head = soup.find_all('head')
                if soup_head:

                    for head in soup_head:
                        if soup.head.link:
                            for head.link in soup.find_all('link', href=True):
                                dots = [x.start(0)
                                        for x in re.finditer('\.', head.link['href'])]
                                if url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                                    data_row.append(-1)
                                    print('10 OK')

                                    raise StopIteration
                                else:
                                    data_row.append(1)
                                    print('10 OK')

                                    raise StopIteration
                        else:
                            data_row.append(1)
                            print('10 OK')
                            raise StopIteration

                else:
                    data_row.append(1)
                    print('10 OK')


            except StopIteration:
                pass

        # 11. Usage of Ports
        try:
            port = domain.split(":")[1]
            if port:
                data_row.append(1)
                print('11 OK')

            else:
                data_row.append(-1)
                print('11 OK')

        except:
            data_row.append(-1)
            print('11 OK')

        # 12. Having HTTPS
        if re.findall(r"^https://", url):
            data_row.append(-1)
            print('12 OK')

        else:
            data_row.append(1)
            print('12 OK')


        # 13. Check External Objects
        i = 0
        success = 0
        if soup == -999:
            data_row.append(-1)
            print('13 OK')

        else:
            for img in soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if url in img['src'] or domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for audio in soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if url in audio['src'] or domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for embed in soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if url in embed['src'] or domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for iframe in soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if url in iframe['src'] or domain in iframe['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            try:
                percentage = success / float(i) * 100
                if percentage < 22.0:
                    data_row.append(1)
                    print('13 OK')

                elif ((percentage >= 22.0) and (percentage < 61.0)):
                    data_row.append(0)
                    print('13 OK')

                else:
                    data_row.append(-1)
                    print('13 OK')

            except:
                data_row.append(1)
                print('13 OK')

        # 14. Check Anchor Tags
        percentage = 0
        i = 0
        unsafe = 0
        if soup == -999:
            data_row.append(-1)
            print('14 OK')

        else:
            for a in soup.find_all('a', href=True):

                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                        url in a['href'] or domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1

            try:
                percentage = unsafe / float(i) * 100

                if percentage < 31.0:
                    data_row.append(1)
                    print('14 OK')

                elif ((percentage >= 31.0) and (percentage < 67.0)):
                    data_row.append(0)
                    print('14 OK')

                else:
                    data_row.append(-1)
                    print('14 OK')

            except:
                data_row.append(1)
                print('14 OK')

        # 15. Check Links in Tags
        i = 0
        success = 0
        if soup == -999:
            data_row.append(-1)
            print('15 OK')
            data_row.append(0)
            print('16 OK')

        else:
            for link in soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if url in link['href'] or domain in link['href'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for script in soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if url in script['src'] or domain in script['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1
            try:
                percentage = success / float(i) * 100

                if percentage < 17.0:
                    data_row.append(1)
                    print('15 OK')

                elif ((percentage >= 17.0) and (percentage < 81.0)):
                    data_row.append(0)
                    print('15 OK')

                else:
                    data_row.append(-1)
                    print('15 OK')

            except:
                data_row.append(1)
                print('15 OK')


            # 16. Domain Check on SFH
            if len(soup.find_all('form', action=True)) == 0:
                data_row.append(-1)
                print('16 OK')

            else:
                for form in soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        data_row.append(1)
                        print('16 OK')

                        break
                    elif url not in form['action'] and domain not in form['action']:
                        data_row.append(0)
                        print('16 OK')

                        break
                    else:
                        data_row.append(-1)
                        print('16 OK')

                        break




        # 17. Automatically Submitting for Emails
        if response == "":
            data_row.append(1)
            print('17 OK')

        else:

            all_forms = soup.find_all('form', action=True)

            if all_forms:

                for form in all_forms:
                    if "mailto:" in form['action']:
                        data_row.append(1)
                        print('17 OK')
                        break
                    else:
                        data_row.append(-1)
                        print('17 OK')
                        break

            else:
                data_row.append(-1)
                print('17 OK')


        # 18. Check if URl is Abnormal
        if response == "" or whois_resp_check == 0:
            data_row.append(1)
            print('18 OK')

        else:
            domain_name = str(whois_response.domain)
            if re.search(domain_name, url):
                data_row.append(-1)
                print('18 OK')

            else:
                data_row.append(1)
                print('18 OK')

        # 19. Check IFrame
        if soup == -999:
            data_row.append(1)
            print('19 OK')

        else:

            iframe_all = soup.find_all('iframe', width=True, height=True, frameBorder=True)

            if iframe_all:

                for iframe in iframe_all:

                    if iframe['width'] == "0" and iframe['height'] == "0" and iframe['frameBorder'] == "0":
                        data_row.append(1)
                        print('19 OK')

                        break
                    else:
                        data_row.append(-1)
                        print('19 OK')

                        break
            else:
                data_row.append(-1)
                print('19 OK')

        # 20. Check onMouseOver
        if response == "":
            data_row.append(1)
            print('20 OK')

        else:
            if re.findall("<script>.+onmouseover.+</script>", response.text):
                data_row.append(1)
                print('20 OK')

            else:
                data_row.append(-1)
                print('20 OK')

        # 21. Check RightClick
        if response == "":
            data_row.append(1)
            print('21 OK')

        else:
            if re.findall(r"event.button ?== ?2", response.text):
                data_row.append(1)
                print('21 OK')

            else:
                data_row.append(-1)
                print('21 OK')

        # 22. Check for popUpWindow
        if response == "":
            data_row.append(1)
            print('22 OK')

        else:
            if re.findall(r"alert\(", response.text):
                data_row.append(1)
                print('22 OK')

            else:
                data_row.append(-1)
                print('22 OK')

        # 23. Check Domain Age
        if response == "":
            data_row.append(1)
            print('23 OK')

        else:
            try:
                registration_date = re.findall(
                    r'Registration Date:</div><div class="df-value">([^<]+)</div>', whois_response.text)[0]
                if diff_month(date.today(), date_parse(registration_date)) >= 6:
                    data_row.append(-1)
                    print('23 OK')

                else:
                    data_row.append(1)
                    print('23 OK')

            except:
                data_row.append(1)
                print('23 OK')

        # 24. Check DNS Record
        dns = 1
        try:
            d = whois.whois(domain)
        except:
            dns = -1
        if dns == -1 or response == "":
            data_row.append(1)
            print('24 OK')

        else:
            if registration_length / 365 <= 1:
                data_row.append(1)
                print('24 OK')

            else:
                data_row.append(-1)
                print('24 OK')

        # 25. Check Web Traffic
        try:
            rank_url = "http://www.alexa.com/siteinfo/" + url

            cj = http.cookiejar.CookieJar()
            mech = mechanize.OpenerFactory().build_opener(mechanize.HTTPCookieProcessor(cj))
            request = mechanize.Request(rank_url)
            tr_response = mech.open(request)
            html = tr_response.read()

            soup = BeautifulSoup(html,'html.parser')

            globalrank = soup.find("div", attrs={"class" : "rankmini-rank"})
            rank = globalrank.text

            rank = ''.join(i for i in rank if i.isdigit())
            rank = int(rank)

            if (rank < 100000):
                data_row.append(-1)
                print('25 OK')

            else:
                data_row.append(0)
                print('25 OK')

        except:
            data_row.append(1)
            print('25 OK')


        # 26. Check No. of Links pointing to page
        if response == "":
            data_row.append(1)
            print('26 OK')

        else:
            number_of_links = len(re.findall(r"<a href=", response.text))
            if number_of_links == 0:
                data_row.append(-1)
                print('26 OK')

            elif number_of_links <= 2:
                data_row.append(0)
                print('26 OK')

            else:
                data_row.append(1)
                print('26 OK')

        # 27. Check Statistical report
        url_match = re.search(
            'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',
            url)
        try:
            ip_address = socket.gethostbyname(domain)
            ip_match = re.search(
                '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
                ip_address)
            if url_match:
                data_row.append(1)
                print('27 OK')

            elif ip_match:
                data_row.append(1)
                print('27 OK')

            else:
                data_row.append(-1)
                print('27 OK')

        except:
            data_row.append(1)
            print('27 OK')

        # 28. Image text Comparison

        try:
            soup_img = BeautifulSoup(requests.get(url, timeout=1).content, "html.parser")
            urls = []
            for img in tqdm(soup_img.find_all("img"), "Extracting site images"):
                img_url = img.attrs.get("src")
                if not img_url:
                    # if img does not contain src attribute, just skip
                    continue
                img_url = urljoin(url, img_url)
                try:
                    pos = img_url.index("?")
                    img_url = img_url[:pos]
                except ValueError:
                    pass
                urls.append(img_url)
            if len(urls) == 0:
                data_row.append(1)
                print('28 OK')
            else:
                no_match = 0
                for img in urls:
                    response = requests.get(img)
                    try:
                        current_img = Image.open(io.BytesIO(response.content))
                        text = pytesseract.image_to_string(current_img)
                        keyword_match = re.search(
                            'label|invoice|post|document|postal|calculations|copy|fedex|statement|financial|dhl|usps|8|notification|n|irs|ups|no|delivery|ticket',
                            text)
                        if keyword_match:
                            data_row.append(1)
                            print('30 OK')
                            no_match = 1
                            break
                        else:
                            continue
                    except IOError:
                        continue
                if no_match == 0:
                    data_row.append(-1)
                    print('28 OK')
        except:
            data_row.append(1)
            print('28 OK')

        return [data_row]
    else:
        return "Invalid URL"
