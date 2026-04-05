package main

import (
	"bufio"
	"cmp"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	version        string
	date           string
	buildDate      time.Time
	goBuildVersion string
)

func getEnv(key string, defaultValue int) int {
	value, exists := os.LookupEnv(key)
	intValue, err := strconv.Atoi(value)
	if !exists || err != nil {
		return defaultValue
	}
	return intValue
}

// Config структура для параметров командной строки
type Config struct {
	LogFile    string
	Date       string
	Since      string
	LastHours  int
	Today      bool
	Yesterday  bool
	Count      bool
	Info       bool
	Rotate     bool
	OutputFile string
	Top        int
	Help       bool
}

// ConnectionInfo структура для хранения информации о подключении
type ConnectionInfo struct {
	IP        string
	Timestamp time.Time
	Line      string
}

// IPStats структура для статистики по IP
type IPStats struct {
	IP        string
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

// LogParser парсер логов
type LogParser struct {
	logFile     string
	timeRegex   *regexp.Regexp
	ipRegex     *regexp.Regexp
	connections []ConnectionInfo
}

type LogRotator struct {
	BaseName  string
	MaxSizeMB int
}

// NewLogRotator создает новый ротатор
func NewLogRotator(baseName string, maxSizeMB int) *LogRotator {
	return &LogRotator{
		BaseName:  baseName,
		MaxSizeMB: maxSizeMB,
	}
}

// RotateIfNeeded проверяет размер и выполняет ротацию если нужно
func (r *LogRotator) RotateIfNeeded() error {
	info, err := os.Stat(r.BaseName)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	maxSizeBytes := r.MaxSizeMB * 1024 * 1024
	if info.Size() < int64(maxSizeBytes) {
		return nil
	}

	// Создаем имя для бэкапа
	timestamp := time.Now().Format("20060102_150405")
	backupName := fmt.Sprintf("%s.%s", r.BaseName, timestamp)

	// Переименовываем
	if err := os.Rename(r.BaseName, backupName); err != nil {
		return fmt.Errorf("rename failed: %w", err)
	}

	fmt.Printf("[ROTATE] Log rotated: %s (%.2f MB) -> %s\n",
		r.BaseName, float64(info.Size())/1024/1024, backupName)

	// Удаляем старые бэкапы
	// TODO

	return nil
}

// NewLogParser создает новый парсер
func NewLogParser(logFile string) *LogParser {
	// Регулярное выражение для извлечения времени:
	// [6][2026-03-31 17:38:12.472158 local]
	// [6][2026-04-05T05:21:41+00:00.1775366501.123 local]
	timeRegex := regexp.MustCompile(`\[\d+\]\[(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:[+-]\d{2}:\d{2})?\.\d+(\.\d*|) local\]`)

	// Регулярное выражение для извлечения IP из "connection from"
	ipRegex := regexp.MustCompile(`connection from (\d+\.\d+\.\d+\.\d+):\d+`)

	return &LogParser{
		logFile:     logFile,
		timeRegex:   timeRegex,
		ipRegex:     ipRegex,
		connections: []ConnectionInfo{},
	}
}

// Parse читает и парсит лог-файл
func (p *LogParser) Parse() error {
	file, err := os.Open(p.logFile)
	if err != nil {
		return fmt.Errorf("cannot open log file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	maxLineSize := 1 * 1024 * 1024 // 1 MB
	// Буфер для больших строк
	buf := make([]byte, maxLineSize)
	scanner.Buffer(buf, maxLineSize)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Проверяем, есть ли "connection from" в строке
		if !strings.Contains(line, "connection from") {
			continue
		}

		// Извлекаем время
		timeMatches := p.timeRegex.FindStringSubmatch(line)
		if len(timeMatches) < 3 {
			continue
		}

		// Парсим время
		timeStr := timeMatches[1] + " " + timeMatches[2]
		timestamp, err := time.Parse("2006-01-02 15:04:05", timeStr)
		if err != nil {
			continue
		}

		// Извлекаем IP
		ipMatches := p.ipRegex.FindStringSubmatch(line)
		if len(ipMatches) < 2 {
			continue
		}

		ip := ipMatches[1]

		p.connections = append(p.connections, ConnectionInfo{
			IP:        ip,
			Timestamp: timestamp,
			Line:      line,
		})
	}

	return scanner.Err()
}

// FilterByDate фильтрует подключения по дате
func (p *LogParser) FilterByDate(date string) []ConnectionInfo {
	var filtered []ConnectionInfo
	for _, conn := range p.connections {
		if conn.Timestamp.Format("2006-01-02") == date {
			filtered = append(filtered, conn)
		}
	}
	return filtered
}

// FilterBySince фильтрует подключения с указанного времени
func (p *LogParser) FilterBySince(since string) []ConnectionInfo {
	sinceTime, err := time.Parse("2006-01-02 15:04:05", since)
	if err != nil {
		return p.connections
	}

	var filtered []ConnectionInfo
	for _, conn := range p.connections {
		if conn.Timestamp.After(sinceTime) || conn.Timestamp.Equal(sinceTime) {
			filtered = append(filtered, conn)
		}
	}
	return filtered
}

// FilterByLastHours фильтрует подключения за последние N часов (от последней записи в логе)
func (p *LogParser) FilterByLastHours(hours int) []ConnectionInfo {
	if len(p.connections) == 0 {
		return []ConnectionInfo{}
	}

	// Находим последнюю временную метку в логах
	lastTime := p.connections[len(p.connections)-1].Timestamp
	threshold := lastTime.Add(-time.Duration(hours) * time.Hour)

	var filtered []ConnectionInfo
	for _, conn := range p.connections {
		if conn.Timestamp.After(threshold) || conn.Timestamp.Equal(threshold) {
			filtered = append(filtered, conn)
		}
	}
	return filtered
}

// FilterByToday фильтрует подключения за последнюю дату в логах
func (p *LogParser) FilterByToday() []ConnectionInfo {
	if len(p.connections) == 0 {
		return []ConnectionInfo{}
	}

	lastDate := p.connections[len(p.connections)-1].Timestamp.Format("2006-01-02")
	return p.FilterByDate(lastDate)
}

// FilterByYesterday фильтрует подключения за предыдущую дату
func (p *LogParser) FilterByYesterday() []ConnectionInfo {
	if len(p.connections) == 0 {
		return []ConnectionInfo{}
	}

	// Получаем все уникальные даты
	dates := make(map[string]bool)
	for _, conn := range p.connections {
		dates[conn.Timestamp.Format("2006-01-02")] = true
	}

	// Сортируем даты
	var dateList []string
	for date := range dates {
		dateList = append(dateList, date)
	}
	sort.Strings(dateList)

	if len(dateList) < 2 {
		return []ConnectionInfo{}
	}

	// Берем предпоследнюю дату
	yesterdayDate := dateList[len(dateList)-2]
	return p.FilterByDate(yesterdayDate)
}

// GetIPStats возвращает статистику по IP
func GetIPStats(connections []ConnectionInfo) []IPStats {
	statsMap := make(map[string]*IPStats)

	for _, conn := range connections {
		if stat, exists := statsMap[conn.IP]; exists {
			stat.Count++
			if conn.Timestamp.After(stat.LastSeen) {
				stat.LastSeen = conn.Timestamp
			}
			if conn.Timestamp.Before(stat.FirstSeen) {
				stat.FirstSeen = conn.Timestamp
			}
		} else {
			statsMap[conn.IP] = &IPStats{
				IP:        conn.IP,
				Count:     1,
				FirstSeen: conn.Timestamp,
				LastSeen:  conn.Timestamp,
			}
		}
	}

	// Преобразуем мапу в слайс
	var stats []IPStats
	for _, stat := range statsMap {
		stats = append(stats, *stat)
	}

	// Сортируем по количеству подключений (по убыванию)
	// sort.Slice(stats, func(i, j int) bool {
	// 	return stats[i].Count > stats[j].Count
	// })

	slices.SortFunc(stats, func(a IPStats, b IPStats) int {
		return cmp.Compare(b.Count, a.Count)
	})

	return stats
}

// PrintUniqueIPs выводит уникальные IP
func PrintUniqueIPs(connections []ConnectionInfo, writer *os.File) {
	ipMap := make(map[string]bool)
	var ips []string

	for _, conn := range connections {
		if !ipMap[conn.IP] {
			ipMap[conn.IP] = true
			ips = append(ips, conn.IP)
		}
	}

	sort.Strings(ips)

	fmt.Fprintf(writer, "Unique IP addresses:\n")
	fmt.Fprintf(writer, "===================\n")
	for i, ip := range ips {
		fmt.Fprintf(writer, "%4d. %s\n", i+1, ip)
	}
	fmt.Fprintf(writer, "\nTotal unique IPs: %d\n", len(ips))
}

// PrintIPStats выводит статистику по IP
func PrintIPStats(stats []IPStats, top int, writer *os.File) {
	fmt.Fprintf(writer, "IP Address                    Connections  First Seen           Last Seen\n")
	fmt.Fprintf(writer, "==============================================================================\n")

	limit := len(stats)
	if top > 0 && top < limit {
		limit = top
	}

	for i := 0; i < limit; i++ {
		stat := stats[i]
		fmt.Fprintf(writer, "%-30s %-12d %-20s %s\n",
			stat.IP,
			stat.Count,
			stat.FirstSeen.Format("2006-01-02 15:04:05"),
			stat.LastSeen.Format("2006-01-02 15:04:05"))
	}

	if top > 0 && top < len(stats) {
		fmt.Fprintf(writer, "\n... and %d more IPs\n", len(stats)-top)
	}

	fmt.Fprintf(writer, "\n==============================================================================\n")
	fmt.Fprintf(writer, "Total unique IPs: %d\n", len(stats))
	fmt.Fprintf(writer, "Total connections: %d\n", func() int {
		total := 0
		for _, stat := range stats {
			total += stat.Count
		}
		return total
	}())
}

// PrintInfo выводит информацию о лог-файле
func PrintInfo(parser *LogParser, writer *os.File) {
	fmt.Fprintf(writer, "=== Log File Information ===\n")
	fmt.Fprintf(writer, "File: %s\n", parser.logFile)

	// Получаем информацию о файле
	if fileInfo, err := os.Stat(parser.logFile); err == nil {
		fmt.Fprintf(writer, "Size: %d bytes (%.2f MB)\n", fileInfo.Size(), float64(fileInfo.Size())/1024/1024)
	}

	fmt.Fprintf(writer, "Total connections in log: %d\n", len(parser.connections))

	if len(parser.connections) > 0 {
		firstTime := parser.connections[0].Timestamp
		lastTime := parser.connections[len(parser.connections)-1].Timestamp
		fmt.Fprintf(writer, "Time range: %s -> %s\n",
			firstTime.Format("2006-01-02 15:04:05"),
			lastTime.Format("2006-01-02 15:04:05"))

		duration := lastTime.Sub(firstTime)
		fmt.Fprintf(writer, "Duration: %.2f hours\n", duration.Hours())
	}

	// Статистика по датам
	dateStats := make(map[string]int)
	for _, conn := range parser.connections {
		date := conn.Timestamp.Format("2006-01-02")
		dateStats[date]++
	}

	if len(dateStats) > 0 {
		fmt.Fprintf(writer, "\n=== Connections per Date ===\n")
		var dates []string
		for date := range dateStats {
			dates = append(dates, date)
		}
		sort.Strings(dates)

		for _, date := range dates {
			fmt.Fprintf(writer, "  %s: %d connections\n", date, dateStats[date])
		}
	}
}

// GetFilterDescription возвращает описание примененного фильтра
func GetFilterDescription(cfg Config, parser *LogParser) string {
	switch {
	case cfg.Date != "":
		return fmt.Sprintf("date = %s", cfg.Date)
	case cfg.Since != "":
		return fmt.Sprintf("since = %s", cfg.Since)
	case cfg.LastHours > 0:
		return fmt.Sprintf("last %d hours (from log end)", cfg.LastHours)
	case cfg.Today:
		return "today (last date in log)"
	case cfg.Yesterday:
		return "yesterday"
	default:
		return "all time"
	}
}

func main() {
	// Параметры командной строки
	var cfg Config

	if version != "" {
		goBuildVersion = runtime.Version()
		buildDate, _ = time.Parse("2006-01-02 03:04:05PM MST", date)
	}

	flag.StringVar(&cfg.LogFile, "f", "logs/mtproxy.log", "Log file path")
	flag.StringVar(&cfg.Date, "d", "", "Filter by date (YYYY-MM-DD)")
	flag.StringVar(&cfg.Since, "s", "", "Filter since time (YYYY-MM-DD HH:MM:SS)")
	flag.IntVar(&cfg.LastHours, "l", 0, "Filter by last N hours")
	flag.BoolVar(&cfg.Today, "t", false, "Filter by today (last date in log)")
	flag.BoolVar(&cfg.Yesterday, "y", false, "Filter by yesterday")
	flag.BoolVar(&cfg.Count, "c", false, "Show count of connections per IP")
	flag.BoolVar(&cfg.Info, "i", false, "Show log file information")
	flag.BoolVar(&cfg.Rotate, "r", false, "Rotate log file")
	flag.StringVar(&cfg.OutputFile, "o", "", "Output file (default: stdout)")
	flag.IntVar(&cfg.Top, "top", 0, "Show top N IPs (with --count)")
	flag.BoolVar(&cfg.Help, "h", false, "Show help")

	flag.Parse()

	// Показываем помощь
	if cfg.Help {
		fmt.Printf("MTProxy Log Analyzer\n\n")
		fmt.Printf("Usage (Version: %s, build info: %s [%s]): %s [options]\n\n", version, goBuildVersion,
			buildDate.Format("2006-01-02 03:04:05PM MST"), os.Args[0])
		fmt.Printf("Options:\n")
		flag.PrintDefaults()
		fmt.Printf("\nExamples:\n")
		fmt.Printf("  %s -f /path/to/mtproxy.log  # Use specific log file\n", os.Args[0])
		fmt.Printf("  %s -t -c                    # Show IPs and counts for today\n", os.Args[0])
		fmt.Printf("  %s -l 6 -c -o report.txt   # Last 6 hours with counts, save to file\n", os.Args[0])
		fmt.Printf("  %s -d 2026-03-31           # Show IPs for specific date\n", os.Args[0])
		fmt.Printf("  %s -i                       # Show log information\n", os.Args[0])
		fmt.Printf("  %s -c -top 10               # Show top 10 IPs by connections\n", os.Args[0])

		return
	}

	if cfg.Rotate {
		maxCapacity := getEnv("MAX_CAPACITY", 2)
		rotator := NewLogRotator(cfg.LogFile, maxCapacity)
		if err := rotator.RotateIfNeeded(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Создаем парсер
	parser := NewLogParser(cfg.LogFile)

	// Парсим лог
	if err := parser.Parse(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Проверяем, есть ли данные
	if len(parser.connections) == 0 {
		fmt.Fprintf(os.Stderr, "No 'connection from' entries found in log file: %s\n", cfg.LogFile)
		os.Exit(1)
	}

	// Применяем фильтры
	var filtered []ConnectionInfo

	switch {
	case cfg.Date != "":
		filtered = parser.FilterByDate(cfg.Date)
	case cfg.Since != "":
		filtered = parser.FilterBySince(cfg.Since)
	case cfg.LastHours > 0:
		filtered = parser.FilterByLastHours(cfg.LastHours)
	case cfg.Today:
		filtered = parser.FilterByToday()
	case cfg.Yesterday:
		filtered = parser.FilterByYesterday()
	default:
		filtered = parser.connections
	}

	// Проверяем, есть ли данные после фильтрации
	if len(filtered) == 0 {
		fmt.Fprintf(os.Stderr, "No connections found with filter: %s\n", GetFilterDescription(cfg, parser))
		fmt.Fprintf(os.Stderr, "Available date range: %s -> %s\n",
			parser.connections[0].Timestamp.Format("2006-01-02"),
			parser.connections[len(parser.connections)-1].Timestamp.Format("2006-01-02"))
		os.Exit(1)
	}

	// Определяем выходной файл
	var output *os.File
	var err error

	output = os.Stdout

	if cfg.OutputFile != "" {
		defer output.Close()
		output, err = os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
	}

	// Выводим заголовок
	fmt.Fprintf(output, "MTProxy Log Analysis\n")
	fmt.Fprintf(output, "====================\n")
	fmt.Fprintf(output, "Filter: %s\n", GetFilterDescription(cfg, parser))
	fmt.Fprintf(output, "Connections found: %d\n\n", len(filtered))

	// Выводим информацию о логах, если запрошено
	if cfg.Info {
		PrintInfo(parser, output)
		return
	}

	// Выводим результаты
	if cfg.Count {
		stats := GetIPStats(filtered)
		PrintIPStats(stats, cfg.Top, output)
	} else {
		PrintUniqueIPs(filtered, output)
	}

	// Если был указан выходной файл, выводим сообщение
	if cfg.OutputFile != "" {
		fmt.Printf("Results saved to: %s\n", cfg.OutputFile)
	}
}
