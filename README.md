# Mini Linux Malware Sandbox

Go ile yazilmis, terminalda calisan sade Linux sandbox prototipi. Bu alet subheli Linux faylini Docker konteyneri icinde izolyasiya olunmus formada icra edir ve onun davranisini log fayllarina yazir.

Toplanan esas melumatlar:

- `strace` ile sistem cagirislarinin logu
- proses snapshot-lari
- socket ve route melumatlari
- sample-in `stdout` ve `stderr` cixislari
- SHA1/SHA256 hash, olcu ve icra metadata-si
- qisa `summary.json` xulasesi

> Vacib: bu layihe tehsil ve laborator analiz ucundur. Namelum ve real malware fayllarini esas is sisteminde isletmeyin. Ayrica VM, snapshot ve izolyasiya olunmus laboratoriya istifade edin.

## Sistem nece isleyir?

1. Istifadeci `mini-sandbox run <sample>` komandasini verir.
2. CLI sample faylini yoxlayir, hash-lerini hesablayir ve yeni `run-id` yaradir.
3. `reports/<run-id>/` qovlugu yaradilir.
4. Docker konteyneri basladilir.
5. Sample konteynere `/sample/input` kimi read-only mount edilir.
6. Konteyner daxilinde `strace` sample-i icra edir.
7. Paralel olaraq proses ve sebekeye aid snapshot-lar toplanir.
8. Timeout bitdikde proses dayandirilir.
9. Neticeler report qovluguna yazilir.
10. CLI terminalda qisa xulase gosterir.

Default davranis tehlukesizlik ucun konservativdir:

- Docker sebekesi sondurulur: `--network none`
- konteyner read-only filesystem ile basladilir
- sample read-only mount edilir
- konteyner non-root `analyst` istifadecisi ile isleyir
- Linux capability-ler silinir: `--cap-drop ALL`
- `no-new-privileges` aktiv edilir
- CPU, memory ve PID limitleri verilir

## Gereksinimler

Bu prototip Linux odaklidir. Esas icra muhiti Linux host olmalidir.

### Lazim olanlar

- Linux host veya Linux VM
- Docker Engine
- Go 1.22 ve ya daha yeni versiya
- Git, isteye bagli olaraq
- Internet, yalniz Docker image build zamani paketlerin yuklenmesi ucun

### Docker image daxilinde qurulan paketler

Bu paketler hosta yox, Docker image-e qurulur:

- `strace`
- `procps`
- `iproute2`
- `coreutils`
- `file`
- `timeout`
- `ca-certificates`

Onlari elle hosta qurmaq lazim deyil. `./mini-sandbox build` zamani Dockerfile bunlari image daxilinde qurur.

## Ubuntu/Debian ucun qurasdirma

### 1. Sistem paketlerini yenile

```bash
sudo apt update
```

### 2. Docker qurasdir

Docker sistemde yoxdursa:

```bash
sudo apt install -y docker.io
sudo systemctl enable --now docker
```

Istifadecini `docker` qrupuna elave etmek ucun:

```bash
sudo usermod -aG docker $USER
```

Bundan sonra terminaldan cixib yeniden daxil olun. Yoxlama:

```bash
docker --version
docker run --rm hello-world
```

### 3. Go qurasdir

Ubuntu/Debian repository-den:

```bash
sudo apt install -y golang-go
go version
```

Go versiyasi kohne olarsa, resmi Go paketinden Go 1.22+ qurasdirin:

```bash
go version
```

Netice `go1.22` ve ya daha yeni olmalidir.

## Layiheni build etmek

Layihe qovlugunda:

```bash
go build -o mini-sandbox ./cmd/mini-sandbox
```

CLI hazir olduqdan sonra yoxlama:

```bash
./mini-sandbox help
```

Docker sandbox image-ni qur:

```bash
./mini-sandbox build
```

Default image adi:

```text
mini-linux-sandbox:latest
```

Basqa image tag vermek ucun:

```bash
./mini-sandbox build --tag my-sandbox:dev
```

## Istifade qaydasi

### Test sample-i islet

```bash
./mini-sandbox run ./samples/test.sh
```

Bu komanda sample-i konteynerde isledir ve neticeleri `reports/<run-id>/` qovluguna yazir.

### Timeout deyeri vermek

Default timeout 15 saniyedir.

```bash
./mini-sandbox run ./samples/test.sh --timeout 30
```

### Report qovlugunu deyismek

```bash
./mini-sandbox run ./samples/test.sh --reports-dir ./my-reports
```

### Xususi Docker image tag ile isletmek

```bash
./mini-sandbox run ./samples/test.sh --tag my-sandbox:dev
```

### Sebekeni aktiv etmek

Default olaraq sebeke sondurulur. Sebeke davranisini analiz etmek lazimdirsa, bunu yalniz izolyasiya edilmis laboratoriyada aktiv edin:

```bash
./mini-sandbox run ./sample --network
```

Timeout ile birlikde:

```bash
./mini-sandbox run ./sample --network --timeout 20
```

### Konteyneri silmeden saxlamaq

Debug ucun konteyneri avtomatik silmeden saxlamaq olar:

```bash
./mini-sandbox run ./sample --keep-container
```

Sonra konteynerleri gormek:

```bash
docker ps -a
```

Lazim olanda silmek:

```bash
docker rm <container-name>
```

## Ssenarilere gore istifade

Bu bolmede komandalar konkret is ssenarilerine gore gosterilir. Her ssenaride meqsed, komanda ve sonra hara baxmaq lazim oldugu yazilib.

### Ssenari 1: Layiheni ilk defe hazirlamaq

Meqsed: CLI-ni build etmek ve Docker sandbox image-ni yaratmaq.

```bash
go build -o mini-sandbox ./cmd/mini-sandbox
./mini-sandbox build
```

Ne vaxt istifade olunur:

- layiheni ilk defe klonladinizsa
- Dockerfile deyisibse
- sandbox image-ni yeniden yaratmaq isteyirsinizse

Yoxlama:

```bash
./mini-sandbox help
docker images | grep mini-linux-sandbox
```

Gozlenen netice: `mini-linux-sandbox:latest` adli Docker image yaranir.

### Ssenari 2: Tehlukesiz sade test icrasi

Meqsed: sistemin duzgun isleyib-islemediyini yoxlamaq.

```bash
./mini-sandbox run ./samples/test.sh
```

Ne vaxt istifade olunur:

- qurasdirmadan sonra ilk yoxlama ucun
- Docker, Go binary ve report yazma prosesini test etmek ucun
- real sample isletmeden evvel sistemin hazir oldugunu gormek ucun

Sonra baxilacaq fayllar:

```bash
ls reports
cat reports/<run-id>/summary.json
cat reports/<run-id>/stdout.log
```

Gozlenen netice: terminalda run ID, report yolu ve qisa syscall xulasesi gorunur.

### Ssenari 3: Namelum Linux script faylini analiz etmek

Meqsed: subheli `.sh` faylinin ne etdiyini izolyasiya olunmus konteynerde gormek.

```bash
./mini-sandbox run ./suspicious.sh --timeout 20
```

Ne vaxt istifade olunur:

- sample shell scriptdirse
- fayl executable deyilse bele `/bin/sh` ile isledilmesini isteyirsinizse
- qisa davranis analizi kifayetdirse

Sonra baxilacaq fayllar:

```bash
cat reports/<run-id>/summary.json
less reports/<run-id>/strace.log
less reports/<run-id>/processes.log
```

Nelere diqqet edin:

- `summary.json` icinde `top_syscalls`
- `strace.log` icinde `openat`, `execve`, `connect`, `socket`
- `processes.log` icinde yeni proseslerin yaranmasi

### Ssenari 4: Linux binary faylini analiz etmek

Meqsed: ELF binary sample-i sandbox daxilinde icra etmek.

```bash
chmod +x ./sample-binary
./mini-sandbox run ./sample-binary --timeout 20
```

Ne vaxt istifade olunur:

- fayl Linux ELF binary-dirse
- sample icrasi ucun executable permission lazimdirsa
- binary-nin hansi fayllara ve proseslere toxundugunu gormek isteyirsinizse

Sonra baxilacaq fayllar:

```bash
cat reports/<run-id>/metadata.json
less reports/<run-id>/strace.log
cat reports/<run-id>/exit_code
```

Qeyd: `metadata.json` icinde SHA1 ve SHA256 hash-ler var. Bu hash-ler sample-i identifikasiya etmek ucun istifade oluna biler.

### Ssenari 5: Uzun isleyen sample ucun timeout artirmaq

Meqsed: default 15 saniye kifayet etmeyende sample-e daha cox vaxt vermek.

```bash
./mini-sandbox run ./sample --timeout 60
```

Ne vaxt istifade olunur:

- sample gec baslayirsa
- davranis bir nece saniyeden sonra ortaya cixirsa
- proses snapshot-larini daha uzun muddet toplamaq lazimdirsa

Sonra baxilacaq fayllar:

```bash
less reports/<run-id>/processes.log
less reports/<run-id>/network.log
```

Diqqet: timeout artdiqca risk ve analiz vaxti da artir. Real malware ucun bunu yalniz izolyasiya olunmus VM-de edin.

### Ssenari 6: Sebeke davranisini analiz etmek

Meqsed: sample-in socket acma, DNS/HTTP/TCP kimi sebeke davranislarini mueyyen etmek.

```bash
./mini-sandbox run ./sample --network --timeout 30
```

Ne vaxt istifade olunur:

- sample-in C2 servere qosulub-qosulmadigini yoxlamaq isteyirsinizse
- `connect`, `socket`, `sendto`, `recvfrom` cagirislari maraqlidirsa
- kontrollu laboratoriyada sebeke monitorinqi aparirsinizsa

Sonra baxilacaq fayllar:

```bash
cat reports/<run-id>/summary.json
less reports/<run-id>/network.log
grep -E "connect|socket|sendto|recvfrom" reports/<run-id>/strace.log
```

Tehlukesizlik qeydi: `--network` default olaraq sondurulub. Bu secimi real malware ucun ancaq ayrica VM ve kontrollu sebeke ile istifade edin.

### Ssenari 7: Neticeleri ayri report qovlugunda saxlamaq

Meqsed: ferqli analizleri ayri qovluqlarda saxlamaq.

```bash
./mini-sandbox run ./sample --reports-dir ./case-001
```

Ne vaxt istifade olunur:

- her incident/case ucun ayri qovluq saxlamaq isteyirsinizse
- laboratoriya hesabatlarini nizamli bolmek lazimdirsa
- bir nece sample analizini qarishdirmamaq isteyirsinizse

Sonra baxilacaq qovluq:

```bash
ls ./case-001
cat ./case-001/<run-id>/summary.json
```

### Ssenari 8: Debug ucun konteyneri saxlayib sonra yoxlamaq

Meqsed: icradan sonra Docker konteynerini avtomatik silmemek.

```bash
./mini-sandbox run ./sample --keep-container
```

Ne vaxt istifade olunur:

- Docker container statusunu sonradan yoxlamaq isteyirsinizse
- container exit kodu ve Docker metadata-si lazimdirsa
- sandbox davranisini debug edirsinizse

Sonra baxilacaq komandalar:

```bash
docker ps -a
docker logs <container-name>
docker inspect <container-name>
```

Temizlemek ucun:

```bash
docker rm <container-name>
```

Qeyd: normal istifade ucun `--keep-container` lazim deyil. Default olaraq konteyner icradan sonra silinir.

### Ssenari 9: Xususi Docker image tag ile islemek

Meqsed: sandbox image-nin ferqli versiyalarini saxlamaq.

```bash
./mini-sandbox build --tag mini-linux-sandbox:lab1
./mini-sandbox run ./sample --tag mini-linux-sandbox:lab1
```

Ne vaxt istifade olunur:

- Dockerfile uzerinde ferqli testler aparirsinizsa
- bir image stabil, digeri test versiyasi kimi saxlanilacaqsa
- CI/lab muhitinde image tag-lerini ayirmaq lazimdirsa

Yoxlama:

```bash
docker images | grep mini-linux-sandbox
```

### Ssenari 10: Analizden sonra suretli xulase oxumaq

Meqsed: tam loglara girmeden sample-in esas davranisini gormek.

```bash
cat reports/<run-id>/summary.json
```

Ne vaxt istifade olunur:

- ilk baxishda sample ne edib anlamaq isteyirsinizse
- top syscall-lari gormek lazimdirsa
- indikatorlari tez yoxlamaq isteyirsinizse

`summary.json` icinde baxilacaq saheler:

- `docker_exit_code`
- `sample_exit_code`
- `top_syscalls`
- `indicators.file_paths`
- `indicators.network_calls`
- `indicators.process_calls`
- `indicators.errors`

### Ssenari 11: Fayl sistemi davranisini yoxlamaq

Meqsed: sample-in hansi fayllari oxudugunu, yoxladigini ve ya acmaga calisdigini gormek.

```bash
./mini-sandbox run ./sample --timeout 20
grep -E "openat|access|stat" reports/<run-id>/strace.log
```

Ne vaxt istifade olunur:

- sample config fayli axtarirsa
- `/etc`, `/tmp`, `/home` kimi path-lere baxib-baxmadigini gormek isteyirsinizse
- fayl yaratma ve oxuma cehdlerini analiz edirsinizse

Qeyd: konteyner read-only basladildigi ucun host fayl sistemi qorunur. Yazmaq ucun esas icaze `/tmp` tmpfs ve `/out` report qovlugudur.

### Ssenari 12: Proses yaratma davranisini yoxlamaq

Meqsed: sample-in basqa proses basladib-baslatmadigini gormek.

```bash
./mini-sandbox run ./sample --timeout 20
grep -E "execve|clone|fork|vfork" reports/<run-id>/strace.log
less reports/<run-id>/processes.log
```

Ne vaxt istifade olunur:

- sample basqa shell, downloader ve ya helper proses acirsa
- proses injection yox, sade proses yaratma davranisini gormek lazimdirsa
- icra zencirini anlamaq isteyirsinizse

### Ssenari 13: Sample-in terminal cixisini oxumaq

Meqsed: sample-in normal ve error cixislarini ayri-ayri gormek.

```bash
cat reports/<run-id>/stdout.log
cat reports/<run-id>/stderr.log
```

Ne vaxt istifade olunur:

- script `echo`, `printf`, `id`, `uname` kimi cixislar verirse
- error mesajlari sample davranisini izah edirse
- sample-in terminala ne yazdigini hesabatda gostermek lazimdirsa

### Ssenari 14: Tam laboratoriya axini

Meqsed: sifirdan baslayib sample analizini tamamlayaraq neticelere baxmaq.

```bash
go build -o mini-sandbox ./cmd/mini-sandbox
./mini-sandbox build
./mini-sandbox run ./samples/test.sh --timeout 20 --reports-dir ./lab-reports
ls ./lab-reports
cat ./lab-reports/<run-id>/summary.json
less ./lab-reports/<run-id>/strace.log
```

Bu axin ne edir:

- CLI-ni build edir
- Docker sandbox image-ni qurur
- test sample-i icra edir
- reportlari `lab-reports` altinda saxlayir
- xulase ve sistem cagirislarini oxumaq imkani verir

## Komandalar

### `build`

Docker sandbox image-ni qurur.

```bash
./mini-sandbox build
```

Secimler:

```text
--tag string    Docker image tag-i
```

Numune:

```bash
./mini-sandbox build --tag mini-linux-sandbox:latest
```

### `run`

Sample faylini sandbox daxilinde icra edir.

```bash
./mini-sandbox run <sample>
```

Secimler:

```text
--tag string          Istifade olunacaq Docker image tag-i
--timeout int         Icra timeout-u, saniye ile. Default: 15
--reports-dir string  Report qovlugu. Default: reports
--network             Konteyner sebekesini aktiv edir
--keep-container      Icradan sonra konteyneri silmir
```

Numune:

```bash
./mini-sandbox run ./samples/test.sh --timeout 20 --reports-dir ./reports
```

## Report fayllari

Her icradan sonra bele struktur yaranir:

```text
reports/
  20260516-203000-a1b2c3d4/
    metadata.json
    stdout.log
    stderr.log
    strace.log
    processes.log
    network.log
    exit_code
    summary.json
```

Fayllarin menasi:

- `metadata.json` - sample yolu, fayl adi, olcu, SHA1/SHA256 hash, timeout, image ve baslama vaxti
- `stdout.log` - sample-in standard cixisi
- `stderr.log` - sample-in error cixisi
- `strace.log` - sistem cagirislarinin tam logu
- `processes.log` - her saniye proses siyahisi snapshot-i
- `network.log` - socket ve route snapshot-lari
- `exit_code` - sample prosesinin exit kodu
- `summary.json` - top syscall-lar, indikatorlar ve qisa xulase

## Numune analiz axini

```bash
go build -o mini-sandbox ./cmd/mini-sandbox
./mini-sandbox build
./mini-sandbox run ./samples/test.sh --timeout 15
```

Sonra report qovlugunu tap:

```bash
ls reports
```

Xulaseni oxu:

```bash
cat reports/<run-id>/summary.json
```

Sistem cagirislarina bax:

```bash
less reports/<run-id>/strace.log
```

Proses snapshot-larina bax:

```bash
less reports/<run-id>/processes.log
```

Sebeke loguna bax:

```bash
less reports/<run-id>/network.log
```

## Sample fayl hazirlamaq

Script sample-i isletmek ucun faylin executable olmasi sert deyil. Fayl executable deyilse, sandbox onu `/bin/sh` ile isletmeye calisir.

Numune:

```bash
cat > sample.sh <<'EOF'
#!/usr/bin/env sh
echo "hello from sample"
id
uname -a
ls -la /tmp
EOF

./mini-sandbox run ./sample.sh
```

Binary sample ucun:

```bash
chmod +x ./sample-binary
./mini-sandbox run ./sample-binary
```

## Limitler

Bu prototip tam malware analiz sistemi deyil.

- Docker kernel-i host ile paylasir.
- Kernel escape riskleri nezeri olaraq mumkundur.
- GUI proqramlari ucun nezerde tutulmayib.
- Windows PE fayllarini native isletmir.
- Internet aktiv edilse, risk artir.
- Davranis analizi sade log ve xulase seviyyesindedir.

## Tehlukesizlik tovsiyeleri

- Real malware-i esas komputerinizde isletmeyin.
- Ayri Linux VM istifade edin.
- VM snapshot yaradib analizden sonra geri qaytarin.
- Mumkundurse interneti sondurun.
- `--network` secimini yalniz kontrollu laboratoriyada istifade edin.
- Host qovluqlarini konteynere yazila bilen formada mount etmeyin.
- Analiz fayllarini yalniz read-only saxlayin.
- Sandbox-dan cixan loglari da ehtiyatla analiz edin.

## Problemler ve hell yollari

### `Docker CLI is required but was not found in PATH`

Docker qurasdirilmayib ve ya PATH-de deyil.

```bash
docker --version
```

Docker qurasdirin ve servisi basladin:

```bash
sudo apt install -y docker.io
sudo systemctl enable --now docker
```

### `permission denied while trying to connect to the Docker daemon`

Istifadeci `docker` qrupunda deyil.

```bash
sudo usermod -aG docker $USER
```

Sonra logout/login edin.

### `sample file not found`

Verdiyiniz yol yanlisdir. Faylin movcud oldugunu yoxlayin:

```bash
ls -la ./samples/test.sh
```

### Docker image tapilmir

Evvel image build edin:

```bash
./mini-sandbox build
```

Xususi tag istifade etmisinizse, `run` zamani eyni tag-i verin:

```bash
./mini-sandbox build --tag my-sandbox:dev
./mini-sandbox run ./sample --tag my-sandbox:dev
```
