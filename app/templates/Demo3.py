import json
import re
import requests
from bs4 import BeautifulSoup
import redis

# 获取电影
def findVideo(url, headers):
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, 'html5lib')
    test = soup.find_all("video")[0]
    soup1 = BeautifulSoup(str(test), 'html5lib')
    ceshi = soup1.find_next("source")

    video_url = ceshi.get("src")

    return video_url


# 定义访问头
headers = {
    'Accept': 'image/webp,image/*,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate, sdch',
    'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36',
}


def findAll(url_list, headers):
    return_data = requests.get(url_list, verify=False)
    # 转为json 数据
    movies = json.loads(return_data.text)

    nub = 1
    for v in movies.get("subjects"):
        print("第 %s 个" % nub)
        nub = nub + 1
        url = v.get("url")
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        div_info = soup.find_all("div", id="info")
        soup1 = BeautifulSoup(str(div_info), 'html5lib')
        span_list = soup1.text.split("<span class='pl'>")[0].split("\n")
        data_area = soup1.find_all("span", property="v:initialReleaseDate")[0].get_text()

        info = soup.find_all("span", property="v:summary")[0].get_text().strip()
        release_time = str(data_area).split("(")[0]
        area = ""
        lenth = ""
        for sp in span_list:
            if sp.startswith("制片国家/地区:"):
                area = sp.split(": ")[1]
            elif sp.startswith("片长:"):
                lenth = re.findall(r"(.+?)分钟", sp.split(": ")[1])[0]

        soup2 = BeautifulSoup(str(soup.find_all("li", class_="label-trailer")), 'html5lib')

        test = soup2.find_next("a")

        try:
            video_url = findVideo(test.get('href'), headers)
        except Exception as err:
            video_url = "--"

        print("影片名称：" + v.get("title"))
        print("影片图片：" + v.get("cover"))
        print("影片星级：" + v.get("rate"))
        print("信息：" + info)
        print("添加时间：" + release_time)
        print("地区：" + area)
        print("时长：" + lenth)
        print("电影地址：" + video_url)
        print("")


def get_movie_url():
    # 定义地址
    count = 0
    nub = 1
    for v in range(1, 2):
        print("第 %s 页" % nub)
        url_list = "https://movie.douban.com/j/search_subjects?type=movie&tag=%E7%83%AD%E9%97%A8&sort=recommend&page_limit=20&page_start=" + str(
            count)
        count = count + 20
        nub = nub + 1
        findAll(url_list, headers)


if __name__ == '__main__':
    get_movie_url()
