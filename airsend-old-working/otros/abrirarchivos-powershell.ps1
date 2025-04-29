#Para abrir archivos uno por uno de la carpeta folderPaTH, y tiene una espera de 4 segundos
#sirve para agregar libros a la biblioteca de smart reader lenovo porque no deja importar todos juntos

# Ruta de la carpeta que contiene los archivos
$folderPath = "C:\Users\nala\Desktop\libros"

Write-Host "Iniciando el script de apertura de archivos..."

# Verifica si la carpeta existe
if (-Not (Test-Path -Path $folderPath)) {
    Write-Host "La carpeta especificada no existe: $folderPath"
    exit
} else {
    Write-Host "Carpeta encontrada: $folderPath"
}

# Obtiene todos los archivos en la carpeta
$files = Get-ChildItem -Path $folderPath -File

if ($files.Count -eq 0) {
    Write-Host "No se encontraron archivos en la carpeta: $folderPath"
    exit
} else {
    Write-Host "Número de archivos encontrados: $($files.Count)"
}

foreach ($file in $files) {
    Write-Host "Abriendo archivo: $($file.FullName)"
    
    try {
        # Inicia el proceso para abrir el archivo y obtiene el objeto del proceso
        $process = Start-Process -FilePath $file.FullName -PassThru
        
        Write-Host "Proceso iniciado para: $($file.Name) (PID: $($process.Id))"
        
        # Espera 4 segundos
        Start-Sleep -Seconds 4
        
        # Cierra el proceso que abrió el archivo
        Stop-Process -Id $process.Id -Force
        Write-Host "Archivo cerrado automáticamente: $($file.Name)"
    }
    catch {
        Write-Host "Error al abrir o cerrar el archivo: $($file.Name). Detalles: $_"
    }
}

Write-Host "Todos los archivos han sido procesados."
Read-Host "Presiona Enter para salir"

