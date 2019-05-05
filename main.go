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
	"time"
)

var (
	FromChina  = 0
	FromOutSea = 1
)

type config struct {
	ListenAddress      string
	ChinaParents       []string
	OutSeaParents      []string
	Timeout            int
	ChinaTimeoutOffset int
	IPDatabase         string
	Debug              bool
	c                  *dns.Client
	s                  *dns.Server
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
	s.c = new(dns.Client)
	s.s = new(dns.Server)
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
		log.Printf("{%s} Parents failed: %s.\n", a, err)
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
		if len(a.Answer) > 1 || len(a.Answer) <= 0 {
			return true, nil
		} else {
			a := a.Answer[0]
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

	select {
	case a := <-answerChan:
		if a.from == FromChina {
			f, err := returnNow(a, r)
			if err != nil {
				log.Printf("[%s] Judge Failed: %s.\n", r.Question[0].String(), err)
				return
			}
			if f {
				err := w.WriteMsg(a.Msg)
				if err != nil {
					log.Printf("[%s] Return Failed: %s.\n", r.Question[0].String(), err)
				}
				return
			} else {
				select {
				case a := <-answerChan:
					err := w.WriteMsg(a.Msg)
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
					err := w.WriteMsg(b.Msg)
					if err != nil {
						log.Printf("[%s] Return Failed: %s.\n", r.Question[0].String(), err)
					}
					return
				} else {
					err := w.WriteMsg(a.Msg)
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
	s.s.Addr = s.ListenAddress
	s.s.Net = "udp"
	s.s.ReusePort = true
	s.s.Handler = s
	err := s.s.ListenAndServe()
	if err != nil {
		log.Fatal("Server DNS Failed: ", err)
	}
}

func main() {
	c := flag.String("c", "", "Config file path.")
	flag.Parse()
	app := config{}
	app.Init(*c)
	app.Run()
}
