from pymongo import MongoClient
import pandas as pd
from bs4 import BeautifulSoup


if __name__ == "__main__":    
    
    client = MongoClient('mongodb://docker:mongopw@localhost:55000/')

    # First, all constant time ones
    result = client['microsurf']['evaluation'].aggregate([
    {
            '$unwind': {
                'path': '$results'
            }
        }, {
            '$addFields': {
                'algorithm': '$results.algorithm'
            }
        }, {
            '$addFields': {
                'compiler': 'gcc'
            }
        }, {
            '$match': {
                'results.leaks.Memory Leak Count': {
                    '$eq': 0
                }, 
                'results.leaks.CF Leak Count': {
                    '$eq': 0
                }
            }
        }, {
            '$addFields': {
                'result': '<span class=\"badge badge-success text-uppercase\">Constant time</span>'
            }
        }
    ])
    df = pd.DataFrame(result)[['framework', 'algorithm', 'toolchain', 'compiler', 'optlvl', 'commit', 'result']]
    txt = df.to_html(escape=False, header=False, index_names=False, index=False).split('\n')
    txt = txt[2:] # remove table def
    txt = txt[:-2] # footer
    
    # load table
    with open('bootstrap-static/index.html', 'r') as f:
        html = f.readlines()

    soup=BeautifulSoup(''.join(html),'html.parser')
    outer_div=soup.find('div',attrs={"class":"tablecontent"})
    outer_div.clear()
    outer_div.append(BeautifulSoup(''.join(txt),'html.parser'))

    lines = soup.prettify()
    lines = lines.split('\n')
    # write back
    with open('bootstrap-static/index.html', 'w') as f:
        f.writelines(lines)
