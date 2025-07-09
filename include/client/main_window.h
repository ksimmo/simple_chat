#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <QMainWindow>
#include <QVBoxLayout>


class MainWindow : public QMainWindow
{
    Q_OBJECT
private:
    QVBoxLayout* contact_layout;
    
public:
    MainWindow(QWidget* parent=nullptr);
    ~MainWindow();
};

#endif