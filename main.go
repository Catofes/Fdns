package main

import (
	"context"
	"encoding/json"
	"flag"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/yl2chen/cidranger"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	FromChina  = 0
	FromOutSea = 1
)

type config struct {
	ListenAddress      string
	TcpListenAddress   string
	ChinaParents       []string
	OutSeaParents      []string
	Timeout            int
	Prefix             string
	CertPath           string
	KeyPath            string
	ChinaTimeoutOffset int
	IPDatabase         string
	Debug              bool
	c                  *dns.Client
	udpServer          *dns.Server
	db                 cidranger.Ranger
}

func (s *config) Init(path string) {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("Read config failed: ", err)
	}
	err = json.Unmarshal(f, s)
	if err != nil {
		log.Fatal(err)
	}
	if len(s.ChinaParents) == 0 || len(s.OutSeaParents) == 0 {
		log.Fatal("China and OutSea Parents missed.")
	}
	if s.Timeout == 0 {
		s.Timeout = 5000
	}
	if s.ChinaTimeoutOffset == 0 {
		s.ChinaTimeoutOffset = 300
	}
	if s.Prefix == "" {
		log.Fatal("Prefix must be 2001:xxx:xxx:xxx:xxx:xxx:")
	}
	s.c = new(dns.Client)
	s.udpServer = new(dns.Server)
	s.db = cidranger.NewPCTrieRanger()
	f, err = ioutil.ReadFile(s.IPDatabase)
	if err != nil {
		log.Fatal("Read IP Database error.")
	}
	ranges := strings.Split(string(f), "\n")
	for _, r := range ranges {
		if len(r) <= 1 {
			return
		}
		if r[0] == '#' {
			continue
		}
		_, network, err := net.ParseCIDR(r)
		if err != nil {
			log.Fatal("CIDR Parse failed.", err)
		}
		err = s.db.Insert(cidranger.NewBasicRangerEntry(*network))
		if err != nil {
			log.Fatal("CIDR Parse failed.", err)
		}
	}
}

func (s *config) LookupOnce(ctx context.Context, m *dns.Msg, a string, r chan *dns.Msg) {
	reply, _, err := s.c.ExchangeContext(ctx, m, a)
	if err != nil {
		log.Printf("[%s] Parents failed: %s.\n", a, err)
		return
	}
	select {
	case r <- reply:
	case <-ctx.Done():
	}
}

func (s *config) LookupMulti(ctx context.Context, m *dns.Msg, a *[]string) (r *dns.Msg, err error) {
	answer := make(chan *dns.Msg)
	c, cancel := context.WithTimeout(ctx, time.Duration(s.Timeout)*time.Millisecond)
	defer cancel()
	for _, v := range *a {
		go s.LookupOnce(c, m, v, answer)
	}
	select {
	case r = <-answer:
		return
	case <-c.Done():
		return nil, errors.New("Timeout")
	}
}

func (s *config) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if r == nil {
		return
	}
	if len(r.Question) <= 0 {
		return
	}

	AFlag := false
	AAAAFlag := false

	if r.Question[0].Qtype == dns.TypeA {
		AFlag = true
	}
	if r.Question[0].Qtype == dns.TypeAAAA {
		r.Question[0].Qtype = dns.TypeA
		AAAAFlag = true
	}

	c, cancel := context.WithTimeout(context.Background(), 2*time.Duration(s.Timeout)*time.Millisecond)
	defer cancel()

	type answer struct {
		*dns.Msg
		from int
	}

	answerChan := make(chan *answer)

	go func(c context.Context) {
		a, err := s.LookupMulti(c, r, &(s.ChinaParents))
		if err != nil {
			log.Printf("[%s] China Failed: %s.\n", r.Question[0].String(), err)
			return
		}
		select {
		case answerChan <- &answer{a, FromChina}:
		case <-c.Done():
		}
	}(c)
	go func(c context.Context) {
		a, err := s.LookupMulti(context.Background(), r, &(s.OutSeaParents))
		if err != nil {
			log.Printf("[%s] OutSea Failed: %s.\n", r.Question[0].String(), err)
			return
		}
		select {
		case answerChan <- &answer{a, FromOutSea}:
		case <-c.Done():
		}
	}(c)

	returnNow := func(a *answer, r *dns.Msg) (bool, error) {
		AAnswer := make([]dns.RR, 0)
		for _, v := range a.Answer {
			if v.Header().Rrtype == dns.TypeA {
				AAnswer = append(AAnswer, v)
			}
		}
		if len(AAnswer) > 1 || len(AAnswer) <= 0 {
			return true, nil
		}
		{
			a := AAnswer[0]
			if a.Header().Rrtype != dns.TypeA {
				return true, nil
			}
			A, e := a.(*dns.A)
			if e != true {
				return false, errors.New("Type assert failed")
			}
			contains, err := s.db.Contains(A.A)
			if err != nil {
				return false, errors.New("Ip Address judge failed")
			}

			if contains {
				if s.Debug {
					log.Printf("[%s] Results below to china.\n", r.Question[0].String())
				}
				return true, nil
			} else {
				if s.Debug {
					log.Printf("[%s] Results not below to china.\n", r.Question[0].String())
				}
				return false, nil
			}
		}
	}

	dns64 := func(in *dns.Msg, c context.Context) (out *dns.Msg) {
		defer func() {
			if s.Debug {
				log.Printf("******************\n%s\n", out.String())
			}
		}()

		out = in.Copy()

		if AFlag {
			out.Answer = make([]dns.RR, 0)
			for _, v := range in.Answer {
				switch v.Header().Rrtype {
				case dns.TypeA:
					A, e := v.(*dns.A)
					if e != true {
						continue
					}
					contains, err := s.db.Contains(A.A)
					if err != nil {
						continue
					}
					if contains {
						out.Answer = append(out.Answer, v)
					}
				case dns.TypeCNAME:
					out.Answer = append(out.Answer, v)
				}

			}
			return out
		}
		if AAAAFlag {
			out.Question[0].Qtype = dns.TypeAAAA
			out.Answer = make([]dns.RR, 0)
			for _, v := range in.Answer {
				switch v.Header().Rrtype {
				case dns.TypeA:
					A, e := v.(*dns.A)
					if e != true {
						continue
					}
					dst := s.Prefix + A.A.String()
					v6 := &dns.AAAA{
						Hdr:  dns.RR_Header{Name: v.Header().Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: v.Header().Ttl},
						AAAA: net.ParseIP(dst),}
					out.Answer = append(out.Answer, v6)
				case dns.TypeCNAME:
					out.Answer = append(out.Answer, v)
				}
			}
		}
		return out
	}

	select {
	case a := <-answerChan:
		if a.from == FromChina {
			f, err := returnNow(a, r)
			if err != nil {
				log.Printf("[%s] Judge Failed: %s.\n", r.Question[0].String(), err)
				return
			}
			if f {
				err := w.WriteMsg(dns64(a.Msg, c))
				if err != nil {
					log.Printf("[%s] Return Failed: %s.\n", r.Question[0].String(), err)
				}
				return
			} else {
				select {
				case a := <-answerChan:
					err := w.WriteMsg(dns64(a.Msg, c))
					if err != nil {
						log.Printf("[%s] Return Failed: %s.\n", r.Question[0].String(), err)
					}
					return
				case <-c.Done():
					return
				}
			}
		} else {
			c, cancel := context.WithTimeout(context.Background(), time.Duration(s.ChinaTimeoutOffset)*time.Millisecond)
			defer cancel()
			select {
			case b := <-answerChan:
				f, err := returnNow(b, r)
				if err != nil {
					log.Printf("[%s] Judge Failed: %s.\n", r.Question[0].String(), err)
					return
				}
				if f {
					err := w.WriteMsg(dns64(b.Msg, c))
					if err != nil {
						log.Printf("[%s] Return Failed: %s.\n", r.Question[0].String(), err)
					}
					return
				} else {
					err := w.WriteMsg(dns64(a.Msg, c))
					if err != nil {
						log.Printf("[%s] Return Failed: %s.\n", r.Question[0].String(), err)
					}
					return
				}
			case <-c.Done():
				return
			}
		}
	case <-c.Done():
		return
	}
}

func (s *config) Run() {
	s.udpServer.Addr = s.ListenAddress
	s.udpServer.Net = "udp"
	s.udpServer.ReusePort = true
	s.udpServer.Handler = s
	wg := sync.WaitGroup{}
	go func() {
		err := s.udpServer.ListenAndServe()
		if err != nil {
			log.Fatal("Server DNS UDP Failed: ", err)
		}
	}()

	go func() {
		err := dns.ListenAndServeTLS(s.TcpListenAddress, s.CertPath, s.KeyPath, s)
		if err != nil {
			log.Printf("Server DNS Failed: %s.\n", err)
			return
		}
	}()
	wg.Add(2)
	wg.Wait()
}

func main() {
	c := flag.String("c", "", "Config file path.")
	flag.Parse()
	app := config{}
	app.Init(*c)
	app.Run()
}
