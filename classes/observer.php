<?php

//被观察者
class Newspaper implements SplSubject {
    private $observers;
    private $content;
    public function __construct(){
        $this->observers = new SplObjectStorage();
    }
    public function attach(SplObserver $observer){
        $this->observers->attach($observer);
    }
    public function detach(SplObserver $observer){
        $this->observers->detach($observer);
    }
    public function notify(){
        foreach ($this->observers as $observer) {
            $observer->update($this);
        }
    }
    public function getContent(){
        return $this->content;
    }
    public function breakOutNews($content) {
        $this->content = $content;
        $this->notify();
    }
}

//观察者
class Reader implements SplObserver {
    private $name;
    public function __construct($name){
        $this->name = $name;
    }
    public function update(SplSubject $subject) {
        echo $this->name .' receive ' . $subject->getContent() . PHP_EOL;
    }
}
echo '<pre>';
$newspaper = new Newspaper('times');

$a = new Reader("a");
$b = new Reader("b");
$c = new Reader("c");
//添加观察者/订阅
$newspaper->attach($a);
$newspaper->attach($b);
$newspaper->attach($c);
//移除观察者
$newspaper->detach($a);
//发布
$newspaper->breakOutNews('news 23333');

