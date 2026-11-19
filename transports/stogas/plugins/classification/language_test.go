package classification

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// prompts are short requests in the languages that people most often write to models. Most are
// one sentence, which the detector reads right or leaves undetermined.
var prompts = []struct{ want, text string }{
	{"en", "Can you help me write a function that parses a CSV file and returns the rows as a list of dictionaries?"},
	{"en", "Summarize the following meeting notes in three bullet points."},
	{"en", "Why does my React component re-render twice when I update the state inside useEffect?"},
	{"en", "What's the difference between a mutex and a semaphore?"},
	{"en", "Fix the failing test in auth_test.go and explain what was wrong."},
	{"en", "thanks, that works"},
	{"en", "Please translate this email into a more formal tone and keep it short."},
	{"de", "Kannst du mir bitte erklären, wie ich in Python eine Liste nach einem Schlüssel sortiere?"},
	{"de", "Fasse den folgenden Text in drei Sätzen zusammen und nenne die wichtigsten Punkte."},
	{"de", "Warum schlägt mein Docker-Build fehl, wenn ich das Image auf dem Server baue?"},
	{"de", "danke, das hat funktioniert"},
	{"fr", "Peux-tu m'aider à écrire une lettre de motivation pour un poste de développeur ?"},
	{"fr", "Explique-moi la différence entre une API REST et GraphQL avec des exemples simples."},
	{"fr", "Résume ce document en cinq points clés, s'il te plaît."},
	{"es", "¿Puedes explicarme cómo funciona la recursión con un ejemplo en JavaScript?"},
	{"es", "Escribe un correo para pedir una reunión con el equipo de ventas la próxima semana."},
	{"es", "¿Cuál es la mejor manera de aprender estadística para ciencia de datos?"},
	{"it", "Potresti spiegarmi come configurare un server Nginx come proxy inverso?"},
	{"it", "Scrivi un breve riassunto di questo articolo sulla politica economica europea."},
	{"pt", "Você pode me ajudar a entender por que meu código Java lança uma NullPointerException?"},
	{"pt", "Escreva uma descrição de produto para uma garrafa térmica de aço inoxidável."},
	{"nl", "Kun je me helpen een SQL-query te schrijven die de totale omzet per maand berekent?"},
	{"nl", "Wat is het verschil tussen een lening met vaste en variabele rente?"},
	{"pl", "Czy możesz mi wyjaśnić, jak działa algorytm sortowania przez scalanie?"},
	{"pl", "Napisz krótki e-mail z przeprosinami za opóźnienie dostawy."},
	{"sv", "Kan du hjälpa mig att skriva ett skript som säkerhetskopierar mina filer varje natt?"},
	{"da", "Kan du forklare, hvordan man opsætter en virtuel maskine i skyen?"},
	{"nb", "Kan du forklare hvordan jeg setter opp en virtuell maskin i skyen?"},
	{"fi", "Voitko selittää, miten konttien orkestrointi toimii Kubernetesissa?"},
	{"cs", "Můžeš mi vysvětlit, jak funguje šifrování veřejným klíčem?"},
	{"ro", "Poți să-mi explici cum funcționează un contract de închiriere pe termen lung?"},
	{"hu", "El tudnád magyarázni, hogyan működik a gépi tanulás egyszerű szavakkal?"},
	{"tr", "Bana Python'da bir sözlüğün nasıl sıralanacağını açıklayabilir misin?"},
	{"id", "Bisakah kamu menjelaskan cara kerja jaringan saraf tiruan dengan bahasa sederhana?"},
	{"vi", "Bạn có thể giải thích cách hoạt động của blockchain một cách đơn giản không?"},
	{"ru", "Можешь объяснить, как работает сборщик мусора в Java?"},
	{"ru", "Напиши короткое письмо коллеге с просьбой перенести встречу на пятницу."},
	{"uk", "Чи можеш ти пояснити, як працює шифрування з відкритим ключем?"},
	{"bg", "Можеш ли да обясниш как работи машинното обучение с прости думи?"},
	{"zh", "你能帮我写一个Python函数来读取CSV文件吗？"},
	{"zh", "请用三句话总结这篇文章的主要观点。"},
	{"ja", "PythonでCSVファイルを読み込む関数を書いてもらえますか？"},
	{"ja", "この文章を三つの要点にまとめてください。"},
	{"ko", "파이썬에서 CSV 파일을 읽는 함수를 작성해 줄 수 있나요?"},
	{"ar", "هل يمكنك أن تشرح لي كيف يعمل التعلم الآلي بكلمات بسيطة؟"},
	{"fa", "می‌توانی توضیح بدهی که یادگیری ماشین چگونه کار می‌کند؟"},
	{"he", "תוכל להסביר לי איך עובדת למידת מכונה במילים פשוטות?"},
	{"hi", "क्या आप मुझे सरल शब्दों में समझा सकते हैं कि मशीन लर्निंग कैसे काम करती है?"},
	{"el", "Μπορείς να μου εξηγήσεις πώς λειτουργεί η μηχανική μάθηση με απλά λόγια;"},
	{"th", "คุณช่วยอธิบายการทำงานของการเรียนรู้ของเครื่องด้วยคำง่ายๆ ได้ไหม"},
	{"en", "```go\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n```\nWhy does this not compile on my machine?"},
	{"en", "Refactor this:\nconst x = arr.map(a => a * 2).filter(b => b > 3);\nconsole.log(x);"},
	{"de", "Hier ist mein Code:\nfor i in range(10):\n    print(i)\nWarum gibt er nur bis 9 aus?"},
	{"en", "ok"},
	{"en", "continue"},
	{"en", "yes"},
}

func TestDetectLanguageNeverGuessesWrong(t *testing.T) {
	detected := 0
	for _, prompt := range prompts {
		got := DetectLanguage(prompt.text)
		switch got {
		case prompt.want:
			detected++
		case Undetermined:
		default:
			t.Errorf("%q: got %s, want %s or %s", prompt.text, got, prompt.want, Undetermined)
		}
	}
	// Two thirds of these one-sentence prompts are long enough for a reliable answer.
	if detected < len(prompts)*2/3 {
		t.Errorf("detected %d of %d prompts", detected, len(prompts))
	}
}

// A paragraph is enough for a reliable answer, also between close languages.
func TestDetectLanguageReadsParagraphs(t *testing.T) {
	for want, text := range map[string]string{
		"en": "I am working on a small web service that stores orders in a database. When two customers place an order at the same time, one of the orders sometimes disappears. Could you explain why this happens and how I can prevent it? Please show me how to use a transaction for this and tell me which isolation level I should choose.",
		"de": "Ich arbeite an einem kleinen Webdienst, der Bestellungen in einer Datenbank speichert. Wenn zwei Kunden gleichzeitig bestellen, verschwindet manchmal eine der Bestellungen. Kannst du mir erklären, warum das passiert und wie ich es verhindern kann? Zeig mir bitte, wie ich dafür eine Transaktion verwende, und sag mir, welche Isolationsstufe ich wählen sollte.",
		"fr": "Je travaille sur un petit service web qui enregistre des commandes dans une base de données. Lorsque deux clients passent une commande en même temps, l'une des commandes disparaît parfois. Peux-tu m'expliquer pourquoi cela arrive et comment je peux l'éviter ? Montre-moi comment utiliser une transaction pour cela et dis-moi quel niveau d'isolation je devrais choisir.",
		"es": "Estoy trabajando en un pequeño servicio web que guarda pedidos en una base de datos. Cuando dos clientes hacen un pedido al mismo tiempo, a veces uno de los pedidos desaparece. ¿Puedes explicarme por qué ocurre esto y cómo puedo evitarlo? Muéstrame cómo usar una transacción para esto y dime qué nivel de aislamiento debería elegir.",
		"it": "Sto lavorando a un piccolo servizio web che salva gli ordini in un database. Quando due clienti effettuano un ordine nello stesso momento, a volte uno degli ordini scompare. Puoi spiegarmi perché succede e come posso evitarlo? Mostrami come usare una transazione per questo e dimmi quale livello di isolamento dovrei scegliere.",
		"pt": "Estou trabalhando em um pequeno serviço web que salva pedidos em um banco de dados. Quando dois clientes fazem um pedido ao mesmo tempo, às vezes um dos pedidos desaparece. Você pode me explicar por que isso acontece e como posso evitar? Mostre-me como usar uma transação para isso e diga qual nível de isolamento eu devo escolher.",
		"nl": "Ik werk aan een kleine webdienst die bestellingen in een database opslaat. Als twee klanten tegelijkertijd een bestelling plaatsen, verdwijnt soms een van de bestellingen. Kun je uitleggen waarom dit gebeurt en hoe ik het kan voorkomen? Laat me zien hoe ik hiervoor een transactie gebruik en vertel me welk isolatieniveau ik moet kiezen.",
		"ru": "Я работаю над небольшим веб-сервисом, который сохраняет заказы в базе данных. Когда два клиента оформляют заказ одновременно, один из заказов иногда исчезает. Можешь объяснить, почему это происходит и как это предотвратить? Покажи, пожалуйста, как использовать для этого транзакцию, и скажи, какой уровень изоляции мне выбрать.",
		"pl": "Pracuję nad małą usługą internetową, która zapisuje zamówienia w bazie danych. Kiedy dwóch klientów składa zamówienie w tym samym czasie, jedno z zamówień czasami znika. Czy możesz wyjaśnić, dlaczego tak się dzieje i jak mogę temu zapobiec? Pokaż mi, jak użyć do tego transakcji, i powiedz, jaki poziom izolacji powinienem wybrać.",
		"tr": "Siparişleri bir veritabanında saklayan küçük bir web hizmeti üzerinde çalışıyorum. İki müşteri aynı anda sipariş verdiğinde, siparişlerden biri bazen kayboluyor. Bunun neden olduğunu ve nasıl önleyebileceğimi açıklayabilir misin? Bunun için bir işlemin nasıl kullanılacağını göster ve hangi yalıtım düzeyini seçmem gerektiğini söyle.",
		"ja": "注文をデータベースに保存する小さなウェブサービスを作っています。二人の顧客が同時に注文すると、注文の一つが消えることがあります。なぜこれが起こるのか、どうすれば防げるのか説明してもらえますか？このためのトランザクションの使い方と、選ぶべき分離レベルを教えてください。",
		"zh": "我正在开发一个把订单保存到数据库的小型网络服务。当两个客户同时下单时，有时其中一个订单会消失。你能解释一下为什么会这样，以及我该如何避免吗？请告诉我如何为此使用事务，以及我应该选择哪种隔离级别。",
	} {
		if got := DetectLanguage(text); got != want {
			t.Errorf("%s paragraph: got %s", want, got)
		}
	}
}

func TestDetectLanguageReadsOnlyTheStart(t *testing.T) {
	german := "Kannst du mir bitte erklären, wie ich in Python eine Liste nach einem Schlüssel sortiere? "
	english := strings.Repeat("Please translate this email into a more formal tone and keep it short. ", 20)
	text := strings.Repeat(german, SampleBytes/len(german)+1) + english
	if got := DetectLanguage(text); got != "de" {
		t.Errorf("got %s, want de", got)
	}
	for _, text := range []string{"", "   ", "12345 !?", "```\n```"} {
		if got := DetectLanguage(text); got != Undetermined {
			t.Errorf("%q: got %s", text, got)
		}
	}
}

func TestSampleSkipsFencedCode(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"Hier ist mein Code:\n```python\nfor i in range(10):\n    print(i)\n```\nWarum gibt er nur bis 9 aus?", "Hier ist mein Code:\nWarum gibt er nur bis 9 aus?"},
		// A fence ends only at a run of its own character at least as long as the run that opened it.
		{"a\n~~~\ncode\n```\nmore code\n~~~\nb", "a\nb"},
		{"a\n````\ncode\n```\nmore code\n`````\nb", "a\nb"},
		{"a\n   ```go\ncode\n   ```\nb", "a\nb"},
		// An unclosed fence hides the rest of the text.
		{"a\n```\ncode", "a\n"},
		// Two backticks, an indented run and inline code are prose.
		{"``\nb", "``\nb"},
		{"    ```\nb", "    ```\nb"},
		{"use `x` here", "use `x` here"},
	} {
		whole := Sample{}
		whole.Write(tc.text)
		if got := whole.Text(); got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.text, got, tc.want)
		}
		// A stream gives the same sample in pieces of any size.
		pieces := Sample{}
		for i := range len(tc.text) {
			pieces.Write(tc.text[i : i+1])
		}
		if got := pieces.Text(); got != tc.want {
			t.Errorf("%q in single bytes: got %q, want %q", tc.text, got, tc.want)
		}
	}
	var german Sample
	german.Write("Hier ist mein Code:\n```python\nfor i in range(10):\n    print(i)\n```\nWarum gibt er nur bis 9 aus? Ich habe die Schleife mehrmals geprüft und verstehe den Fehler nicht.")
	if got := DetectLanguage(german.Text()); got != "de" {
		t.Errorf("German around code: got %s", got)
	}
}

func TestSampleStopsAtItsSizeOnACharacterBoundary(t *testing.T) {
	var sample Sample
	sample.Write("a" + strings.Repeat("ä", SampleBytes))
	if !sample.Full() {
		t.Fatal("sample is not full")
	}
	text := sample.Text()
	if len(text) != SampleBytes-1 || !utf8.ValidString(text) {
		t.Fatalf("sample holds %d bytes, valid %v", len(text), utf8.ValidString(text))
	}
	sample.Write("more")
	if sample.Text() != text {
		t.Fatal("a full sample changed")
	}
}

func BenchmarkDetectLanguage(b *testing.B) {
	text := strings.Repeat("Kannst du mir bitte erklären, wie ich in Python eine Liste nach einem Schlüssel sortiere? ", 8)[:SampleBytes]
	b.SetBytes(SampleBytes)
	for b.Loop() {
		DetectLanguage(text)
	}
}

func BenchmarkSampleCode(b *testing.B) {
	text := "```go\n" + strings.Repeat("\tfmt.Println(\"hello, world\")\n", 1<<15) + "```\n"
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		var sample Sample
		sample.Write(text)
	}
}
