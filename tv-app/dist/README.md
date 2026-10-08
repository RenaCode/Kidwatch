Tu CI kladzie `kidwatch-tv.apk` przed `docker build` (job `tv-app` w
.github/workflows/docker-publish.yml). Obraz kopiuje ten katalog do
`/app/tv-app/`, skad panel instaluje aplikacje na telewizor przez ADB.
Lokalnie katalog jest pusty - obraz buduje sie bez APK.
