# Project 2
the training and testing data :https://drive.google.com/file/d/18RFi1OurkNKIek2yILZuN7xW39hHcSs9/view
There are three file:wireshark_preprocess, main, random_gen_testcase.
## Preprocessing 
The user behavior has three log file (wireshark,sysmon,and security), we preprocessing the wireshark log by 'wireshark_preprocess' file and extract the IP information into  "Person_X_IP.txt" data.
## main 
After preprocessing, run the main file , can get the predict like below
```sh
testcase 1: person 1
testcase 2: person 2 
```
hyperparameter: 
- testing_dir ='Example test'   (if need to test the generate data, change this to 'Test')
- testing_num= test_num_person=2 (to identify how many test data need to predict)
- train_num_person=6 (to identify how many test data)
## Generate test data
In order to test more, we write a 'random_gen_testcase', which can generate the three file need in main.py and no need to preprocessing because it generate the 'Person_X_IP.txt' file.

hyperparameter: 
- sub_length=0.2 (to extract how many portion to be testing data from the original training data)


## Python environment
Can run sucessfully in this enviroment
```sh
$ pip list
Package                            Version
---------------------------------- ---------
absl-py                            0.8.1
alabaster                          0.7.12
anaconda-client                    1.7.2
anaconda-navigator                 1.9.7
anaconda-project                   0.8.3
asn1crypto                         1.0.1
astor                              0.8.0
astroid                            2.3.1
astropy                            3.2.1
atomicwrites                       1.3.0
attrs                              19.2.0
Babel                              2.7.0
backcall                           0.1.0
backports.functools-lru-cache      1.5
backports.os                       0.1.1
backports.shutil-get-terminal-size 1.0.0
backports.tempfile                 1.0
backports.weakref                  1.0.post1
beautifulsoup4                     4.8.0
bitarray                           1.0.1
bkcharts                           0.2
bleach                             3.1.0
bokeh                              1.3.4
boto                               2.49.0
Bottleneck                         1.2.1
certifi                            2019.9.11
cffi                               1.12.3
chardet                            3.0.4
Click                              7.0
cloudpickle                        1.1.1
clyent                             1.2.2
colorama                           0.4.1
comtypes                           1.1.7
conda                              4.7.12
conda-build                        3.18.9
conda-package-handling             1.6.0
conda-verify                       3.4.2
contextlib2                        0.6.0
cryptography                       2.7
cycler                             0.10.0
Cython                             0.29.13
cytoolz                            0.10.0
dask                               2.5.2
decorator                          4.4.0
defusedxml                         0.6.0
distributed                        2.5.2
Django                             2.2.7
docutils                           0.15.2
entrypoints                        0.3
et-xmlfile                         1.0.1
fastcache                          1.1.0
filelock                           3.0.12
Flask                              1.1.1
fsspec                             0.5.2
future                             0.17.1
gast                               0.2.2
gevent                             1.4.0
glob2                              0.7
google-pasta                       0.1.8
greenlet                           0.4.15
grpcio                             1.25.0
gym                                0.15.4
gym-unity                          0.11.0
h5py                               2.9.0
HeapDict                           1.0.1
html5lib                           1.0.1
idna                               2.8
image                              1.5.27
imageio                            2.6.0
imagesize                          1.1.0
importlib-metadata                 0.23
imutils                            0.5.3
ipykernel                          5.1.2
ipython                            7.8.0
ipython-genutils                   0.2.0
ipywidgets                         7.5.1
isort                              4.3.21
itsdangerous                       1.1.0
jdcal                              1.4.1
jedi                               0.15.1
Jinja2                             2.10.3
joblib                             0.13.2
json5                              0.8.5
jsonschema                         3.0.2
keyboard                           0.13.4
keyring                            18.0.0
kiwisolver                         1.1.0
lazy-object-proxy                  1.4.2
libarchive-c                       2.8
llvmlite                           0.29.0
locket                             0.2.0
lxml                               4.4.1
Markdown                           3.1.1
MarkupSafe                         1.1.1
matplotlib                         3.1.1
mccabe                             0.6.1
menuinst                           1.4.16
mistune                            0.8.4
mkl-fft                            1.0.14
mkl-random                         1.1.0
mkl-service                        2.3.0
mlagents-envs                      0.11.0
mock                               3.0.5
more-itertools                     7.2.0
MouseInfo                          0.1.2
mpmath                             1.1.0
msgpack                            0.6.1
multipledispatch                   0.6.0
navigator-updater                  0.2.1
nbconvert                          5.6.0
nbformat                           4.4.0
networkx                           2.3
nltk                               3.4.5
nose                               1.3.7
notebook                           6.0.1
numba                              0.45.1
numexpr                            2.7.0
numpy                              1.16.5
numpydoc                           0.9.1
olefile                            0.46
opencv-python                      4.1.1.26
openpyxl                           3.0.0
opt-einsum                         3.1.0
packaging                          19.2
pandas                             0.25.1
pandocfilters                      1.4.2
parso                              0.5.1
partd                              1.0.0
path.py                            12.0.1
pathlib2                           2.3.5
patsy                              0.5.1
pep8                               1.7.1
pickleshare                        0.7.5
Pillow                             6.2.0
pip                                19.2.3
pkginfo                            1.5.0.1
pluggy                             0.13.0
ply                                3.11
prometheus-client                  0.7.1
prompt-toolkit                     2.0.10
protobuf                           3.10.0
psutil                             5.6.3
py                                 1.8.0
PyAutoGUI                          0.9.48
pycodestyle                        2.5.0
pycosat                            0.6.3
pycparser                          2.19
pycrypto                           2.6.1
pycurl                             7.43.0.3
pyflakes                           2.1.1
PyGetWindow                        0.0.8
pyglet                             1.3.2
Pygments                           2.4.2
pylint                             2.4.2
PyMsgBox                           1.0.7
pynput                             1.4.5
pyodbc                             4.0.27
pyOpenSSL                          19.0.0
pyparsing                          2.4.2
pyperclip                          1.7.0
pyreadline                         2.1
PyRect                             0.1.4
pyrsistent                         0.15.4
PyScreeze                          0.1.25
PySocks                            1.7.1
pytest                             5.2.1
pytest-arraydiff                   0.3
pytest-astropy                     0.5.0
pytest-doctestplus                 0.4.0
pytest-openfiles                   0.4.0
pytest-remotedata                  0.3.2
python-dateutil                    2.8.0
PyTweening                         1.0.3
pytz                               2019.3
PyWavelets                         1.0.3
pywin32                            223
pywinpty                           0.5.5
PyYAML                             5.1.2
pyzmq                              18.1.0
QtAwesome                          0.6.0
qtconsole                          4.5.5
QtPy                               1.9.0
requests                           2.22.0
rope                               0.14.0
ruamel-yaml                        0.15.46
scikit-image                       0.15.0
scikit-learn                       0.21.3
scipy                              1.3.1
seaborn                            0.9.0
Send2Trash                         1.5.0
setuptools                         41.4.0
simplegeneric                      0.8.1
singledispatch                     3.4.0.3
six                                1.12.0
sklearn                            0.0
snowballstemmer                    2.0.0
sortedcollections                  1.1.2
sortedcontainers                   2.1.0
soupsieve                          1.9.3
Sphinx                             2.2.0
sphinxcontrib-applehelp            1.0.1
sphinxcontrib-devhelp              1.0.1
sphinxcontrib-htmlhelp             1.0.2
sphinxcontrib-jsmath               1.0.1
sphinxcontrib-qthelp               1.0.2
sphinxcontrib-serializinghtml      1.1.3
sphinxcontrib-websupport           1.1.2
spyder                             3.3.6
spyder-kernels                     0.5.2
SQLAlchemy                         1.3.9
sqlparse                           0.3.0
statsmodels                        0.10.1
sympy                              1.4
tables                             3.5.2
termcolor                          1.1.0
terminado                          0.8.2
testpath                           0.4.2
toolz                              0.10.0
tornado                            6.0.3
tqdm                               4.36.1
traitlets                          4.3.3
unicodecsv                         0.14.1
urllib3                            1.24.2
wcwidth                            0.1.7
webencodings                       0.5.1
Werkzeug                           0.16.0
wheel                              0.33.6
widgetsnbextension                 3.5.1
win-inet-pton                      1.1.0
win-unicode-console                0.5
wincertstore                       0.2
wrapt                              1.11.2
xlrd                               1.2.0
XlsxWriter                         1.2.1
xlwings                            0.15.10
xlwt                               1.3.0
zict                               1.0.0
zipp                               0.6.0
```


