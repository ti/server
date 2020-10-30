package tcpproxy

import (
	"context"
	"io"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
)

type Proxy struct {
	from      string
	to        string
	ctx       context.Context
	cancelFun context.CancelFunc
	log       *log.Entry
}

func NewProxy(from, to string) *Proxy {
	ctx, cancelFun := context.WithCancel(context.Background())
	return &Proxy{
		from:      from,
		to:        to,
		ctx:       ctx,
		cancelFun: cancelFun,
		log: log.WithFields(log.Fields{
			"from": from,
			"to":   to,
		}),
	}
}

func (p *Proxy) Start() error {
	listener, err := net.Listen("tcp", p.from)
	if err != nil {
		return err
	}
	go p.run(listener)
	return nil
}

func (p *Proxy) Stop() {
	p.cancelFun()
}

func (p *Proxy) run(listener net.Listener) {
	for {
		select {
		case <-p.ctx.Done():
			listener.Close()
			return
		default:
			connection, err := listener.Accept()
			if err == nil {
				go p.handle(connection)
			} else {
				p.log.WithField("err", err).Errorln("Error accepting conn")
			}
		}
	}
}

func (p *Proxy) handle(connection net.Conn) {
	defer connection.Close()
	remote, err := net.Dial("tcp", p.to)
	if err != nil {
		p.log.WithField("err", err).Errorln("Error dialing remote host")
		return
	}
	defer remote.Close()
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go p.copy(remote, connection, wg)
	go p.copy(connection, remote, wg)
	go func() {
		wg.Wait()
		p.cancelFun()
	}()
	select {
	case <-p.ctx.Done():
		return
	}
}

func (p *Proxy) copy(from, to net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	select {
	case <-p.ctx.Done():
		return
	default:
		if _, err := io.Copy(to, from); err != nil {
			p.log.WithField("err", err).Errorln("Error from copy")
			p.Stop()
			return
		}
	}
}
