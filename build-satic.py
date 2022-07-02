from pymongo import MongoClient
import pandas as pd
from bs4 import BeautifulSoup
import base64
import glob


if __name__ == "__main__":    
    
    client = MongoClient('mongodb://docker:mongopw@localhost:55000/')

    # First, all constant time ones
    result = client['microsurf']['evaluation2'].aggregate([
    {
            '$unwind': {
                'path': '$results'
            }
        }, {
            '$addFields': {
                'algorithm': '$results.algorithm'
            }
        }, {
            '$match': {
                'results.Memory Leak Count': {
                    '$eq': 0
                }, 
                'results.CF Leak Count': {
                    '$eq': 0
                }
            }
        }, {
            '$addFields': {
                'result': '<span class=\"badge badge-success text-uppercase\">Constant time</span>'
            }
        }
    ])
    txt = []
    try:
        df = pd.DataFrame(result)[['framework', 'algorithm', 'toolchain', 'compiler', 'optlvl', 'commit', 'result']]
        txt = df.to_html(escape=False, header=False, index_names=False, index=False).split('\n')
        txt = txt[2:] # remove table def
        txt = txt[:-2] # footer
    except Exception:
        pass
    
    result = client['microsurf']['evaluation'].aggregate([
        {
            '$unwind': {
                'path': '$results'
            }
        }, {
            '$addFields': {
                'algorithm': '$results.algorithm'
            }
        },
        {
            '$addFields': {
                'b64': '$results.result'
            }
        },
         {
            '$match': {
                '$or': [
                    {
                        'results.Memory Leak Count': {
                            '$gt': 0
                        }
                    }, {
                        'results.CF Leak Count': {
                            '$gt': 0
                        }
                    }
                ]
            }
        }, {
            '$addFields': {
                'result': '<span class=\"badge badge-danger text-uppercase\">Not Constant time</span>'
            }
        }
        ])
    txt2 = []
    try:
        df = pd.DataFrame(result)
        for i in range(len(df)):
            row = df[i:i+1]
            b64bytes = base64.b64decode(str(row['b64'].values[0]))
            import zipfile
            with open(f'/tmp/{str(row["_id"].values[0])}.zip', 'wb') as f:
                f.write(b64bytes)
            with zipfile.ZipFile(f"/tmp/{str(row['_id'].values[0])}.zip","r") as zip_ref:
                    zip_ref.extractall(f"/tmp/res-{str(row['_id'].values[0])}")
            htmlfile = glob.glob(f"/tmp/res-{str(row['_id'].values[0])}/**/*.html", recursive=True)[-1]
            

            with open('bootstrap-static/results/template.html', 'r') as f:
                html = f.readlines()

            with open(htmlfile, 'r') as f:
                html_report = f.readlines()

            soup=BeautifulSoup(''.join(html),'html.parser')
            outer_div=soup.find('div',attrs={"class":"results-body"})
            outer_div.clear()
            outer_div.append(BeautifulSoup(''.join(html_report),'html.parser'))

            lines = soup.prettify()
            lines = lines.split('\n')
            # write back
            with open(f'bootstrap-static/results/{str(row["_id"].values[0])}.html', 'w') as f:
                f.writelines(lines)

        dftable = df[['framework', 'algorithm', 'toolchain', 'compiler', 'optlvl', 'commit', 'result', '_id']]
        txt2 = dftable.to_html(escape=False, header=False, index_names=False, index=False).split('\n')
        txt2 = txt2[2:] # remove table def
        txt2 = txt2[:-2] # footer
    except Exception as e:
        print(str(e))

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
            '$match': {
                '$or': [
                    {
                        'results.Memory Leak Count': {
                            '$eq': -1
                        }
                    }, {
                        'results.CF Leak Count': {
                            '$eq': -1
                        }
                    }
                ]
            }
        }, {
            '$addFields': {
                'result': '<span class=\"badge badge-info text-uppercase\">Algorithm not supported</span>'
            }
        }
        ])
    txt3 = []
    try:
        df = pd.DataFrame(result)[['framework', 'algorithm', 'toolchain', 'compiler', 'optlvl', 'commit', 'result']]
        txt3 = df.to_html(escape=False, header=False, index_names=False, index=False).split('\n')
        txt3 = txt3[2:] # remove table def
        txt3 = txt3[:-2] # footer
    except Exception:
        pass

    result = client['microsurf']['evaluation'].aggregate([
        {
            '$unwind': {
                'path': '$results'
            }
        }, {
            '$addFields': {
                'algorithm': 'n/a'
            }
        }, {
            '$match': {
                '$or': [
                    {
                        'results.Memory Leak Count': {
                            '$eq': -2
                        }
                    }, {
                        'results.CF Leak Count': {
                            '$eq': -2
                        }
                    }
                ]
            }
        }, {
            '$addFields': {
                'result': '<span class=\"badge badge-warning text-uppercase\">Compilation failed</span>'
            }
        }
        ])
    txt4 = []
    try:
        df = pd.DataFrame(result)[['framework', 'algorithm', 'toolchain', 'compiler', 'optlvl', 'commit', 'result']]
        txt4 = df.to_html(escape=False, header=False, index_names=False, index=False).split('\n')
        txt4 = txt4[2:] # remove table def
        txt4 = txt4[:-2] # footer
    except Exception:
        pass

    txt = txt + txt2 + txt3 + txt4

    # load table
    with open('bootstrap-static/index.html', 'r') as f:
        html = f.readlines()

    soup=BeautifulSoup(''.join(html),'html.parser')
    outer_div=soup.find('div',attrs={"class":"tablecontent"})
    outer_div.clear()
    outer_div.append(BeautifulSoup(''.join(txt),'html.parser'))


    rows = soup.findAll('tr')

    for r in rows:
        cols = r.findAll('td')
        try:
            report_path = f"results/{str(cols[-1].renderContents().strip())[2:-1]}.html"
            r['data-href'] = report_path
        except Exception:
            pass

    lines = soup.prettify()
    lines = lines.split('\n')
    # write back
    with open('bootstrap-static/index.html', 'w') as f:
        f.writelines(lines)
